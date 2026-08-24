# Vault PKI ACME Demo — In-Depth Guide

A complete walkthrough of how a Python microservice automatically obtains its TLS certificate
from HashiCorp Vault using the ACME protocol (http-01 challenge).

> **Deutsche Version:** [README.de.md](README.de.md)

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Technical Background: ACME & Nonces](#2-technical-background-acme--nonces)
3. [Vault PKI Setup](#3-vault-pki-setup)
4. [Starting the Demo (Manual)](#4-starting-the-demo-manual)
5. [Starting the Demo with an AI Assistant](#5-starting-the-demo-with-an-ai-assistant)
6. [Testing the Endpoints](#6-testing-the-endpoints)
7. [Live Demo: Automatic Certificate Renewal](#7-live-demo-automatic-certificate-renewal)
8. [Troubleshooting](#8-troubleshooting)
9. [Project Structure](#9-project-structure)

---

## 1. Architecture

```
Mac Host
├── Vault Enterprise (Docker)
│   ├── Container:  vault-2.0.0
│   ├── Port:       8200 (HTTP API + UI)
│   ├── Port:       8201 (Raft Cluster)
│   ├── Storage:    Raft (vault-data/ volume)
│   └── PKI Engine
│         ├── pki       → Root CA
│         └── pki_int   → Intermediate CA + ACME Endpoint
│
└── Python Microservice (Docker)
      ├── Container:  vault-acme-demo
      ├── Port 80:    ACME http-01 Challenge Server (temporary)
      └── Port 8443:  HTTPS API (FastAPI)
            GET /      → Health + certificate info
            GET /cert  → Full certificate details as JSON

Docker Network: dev-network
  vault-2.0.0      → DNS name for the Vault container
  amar-demo.local  → DNS alias for the demo container (for ACME challenge)
```

### ACME Flow Overview

```
Demo Container                    Vault (ACME)
     |                                |
     |  GET /acme/directory           |
     | ------------------------------------------------------>|
     | <-- directory URLs ------------------------------------|
     |                                |
     |  HEAD /acme/new-nonce          |
     | ------------------------------------------------------>|
     | <-- Replay-Nonce: abc123 ------------------------------|
     |                                |
     |  POST /acme/new-account        |
     | ------------------------------------------------------>|
     | <-- account URL --------------------------------------- |
     |                                |
     |  POST /acme/new-order          |
     | ------------------------------------------------------>|
     | <-- order + auth URLs ----------------------------------|
     |                                |
     |  [Challenge Server Port 80]    |
     |  POST /acme/challenge          |
     | ------------------------------------------------------>|
     |              Vault validates:  |
     |         GET /.well-known/...   |
     | <------------------------------------------------------|
     | (Challenge Server responds)    |
     | -----------------------------------------------------> |
     |                                |
     |  POST /acme/order/finalize     |
     | ------------------------------------------------------>|
     | <-- fullchain.pem -------------------------------------|
     |                                |
     |  [HTTPS Server Port 8443]      |
     |  starts with new certificate   |
```

### ACME Flow — Step by Step

Think of ACME as an automated counter where your service collects an official TLS certificate
fully automatically, without any human intervention. The process has five logical steps.

---

#### Step 1: Where do I find you? — The Directory

Before doing anything, the service asks Vault:
**"What addresses do I need to contact?"**

Vault responds with a directory — a list of all URLs needed for the rest of the process:
where to register, where to place an order, where to pick up a one-time code.

> This is important because the service must not know these addresses in advance —
> the ACME standard requires the server to always provide them fresh.
> This way Vault can change its internal URLs at any time without requiring client updates.

---

#### Step 2: Prove you are not an attacker — The Nonce

Every message the service sends to Vault must contain a **one-time code** — the **Nonce**.

**Why?** Imagine someone intercepts the communication and records a valid certificate request.
Without a one-time code, they could simply replay this request and obtain another certificate.

With a nonce that is impossible: Vault issues a code that may only be used **exactly once**.
After that it is worthless. After every response, Vault automatically provides a new code for the
next step — the service never needs to ask for one explicitly.

> **In this demo:** This is exactly where the troubleshooting effort was spent.
> Vault generated the one-time code internally but did not include it in the response —
> because a security filter was blocking it.
> Fix: Explicitly marking the `Replay-Nonce` header as allowed.

---

#### Step 3: Who are you? — Registration

The service creates a **key pair** (like a digital ID) and registers it with Vault. From this
moment on, it signs all its messages with this key.

Vault then knows: these requests really come from this service — not from someone impersonating it.

> This key has nothing to do with the final TLS certificate.
> It is only used for communication with Vault during the ACME process.

---

#### Step 4: Prove you own the domain — The Challenge

This is the heart of ACME.

Vault says: **"You want a certificate for `amar-demo.local` — prove you control this domain."**

Here is how the proof works (`http-01 challenge`):

```
1. Vault issues a random token, e.g.:  3MuuQcvMXn8cV-2-QGUdh34dOoMU

2. The service places this token on port 80 of the domain:
   http://amar-demo.local/.well-known/acme-challenge/3MuuQcvMXn8cV-2-QGUdh34dOoMU

3. The service tells Vault: "I am ready, go ahead and check."

4. Vault fetches this URL itself and verifies the token.

5. If correct → domain control proven → Vault issues the certificate.
```

> **Why is this secure?** Only whoever truly controls the domain can respond on port 80.
> An attacker might intercept the request — but they cannot respond on the domain.
>
> In this demo, the Python service briefly listens on port 80 and responds to exactly
> that one URL. Vault reaches it via the Docker network DNS alias `amar-demo.local`.

---

#### Step 5: Pick up the certificate

Once domain control is proven, the service sends a **Certificate Signing Request (CSR)** to Vault
containing the domain and the public key to embed. Vault's Intermediate CA signs the certificate
and sends it back. The service saves it as `cert.pem` with the private key as `key.pem`, then
starts the HTTPS server.

---

#### Two Keys — A Common Misconception

There are **two separate key pairs** in this process that have nothing to do with each other:

| | Account Key | Domain Key |
|---|---|---|
| **Purpose** | Communication with Vault during ACME | The TLS certificate itself |
| **Who sees it?** | Only Vault | Every browser opening an HTTPS connection |
| **Lifespan** | Only during ACME | As long as the certificate is valid |
| **In the certificate?** | No | Yes |

> Simplified: the account key is your ID at the counter.
> The domain key is the key for the lock on your front door.

---

## 2. Technical Background: ACME & Nonces

### What is ACME?

ACME (Automatic Certificate Management Environment) is a protocol (RFC 8555) that standardizes
the automatic issuance and renewal of TLS certificates. Let's Encrypt uses ACME — HashiCorp Vault
implements it as well inside the PKI engine.

### Why do nonces exist?

ACME requests are signed JSON objects (JWS — JSON Web Signature). Without an anti-replay
mechanism, an attacker could resend an old valid request and trigger unwanted actions
(e.g. re-issue or revoke a certificate).

**A nonce (Number used once) is a unique random value** issued by the server. The client must
embed this value in every signed request. The server accepts each nonce value exactly once.

### The Nonce Mechanism in Detail (RFC 8555 §6.5 & §7.2)

#### Step 1 — Fetch a nonce

The client makes a `HEAD` (or `GET`) request to the `newNonce` endpoint:

```
HEAD /v1/pki_int/roles/amar-demo/acme/new-nonce HTTP/1.1
Host: vault-2.0.0:8200
```

Vault responds with a fresh nonce in the header:

```
HTTP/1.1 200 OK
Replay-Nonce: dmF1bHQwlvrchXsw-TYmqQU2CSsFARiJB5VpWzBjVN-w33HGrSjzQy9ShGclXg
Cache-Control: no-store
```

The nonce value is Base64url-encoded and internally time-limited. Vault stores it in the PKI
engine storage. After a single use, it is invalidated.

#### Step 2 — Embed the nonce in JWS

Every ACME request is sent as a JWS (JSON Web Signature). The structure:

```json
{
  "protected": "<base64url({
    'alg': 'RS256',
    'jwk': { ...public key... },
    'nonce': 'dmF1bHQwlvrchXsw-TYmqQU2CSsFARiJB5VpWzBjVN-w33HGrSjzQy9ShGclXg',
    'url': 'http://vault-2.0.0:8200/v1/pki_int/roles/amar-demo/acme/new-account'
  })>",
  "payload": "<base64url({ ...request body... })>",
  "signature": "<RSA signature over protected.payload>"
}
```

The `nonce` in the `protected` header binds the request to exactly this moment in time.

#### Step 3 — Vault validates the nonce

On receipt, Vault checks:
1. Is the nonce value known (present in storage)?
2. Has it not been used yet?
3. Is the JWS signature valid?

If the nonce is missing or already used, Vault responds with:
```json
{ "type": "urn:ietf:params:acme:error:badNonce" }
```
The client must then fetch a new nonce and retry.

#### Step 4 — Recycle the nonce from POST responses

After every successful POST, Vault automatically returns a new nonce in the response header.
The client does not always need to call the `newNonce` endpoint — it can reuse the nonce from
the last response.

### Vault-Specific Detail: `allowed_response_headers`

For security reasons, Vault filters HTTP response headers. Non-standard headers such as
`Replay-Nonce` are **not** passed through by default, even if the internal handler sets them.

For ACME, the PKI mount must be explicitly configured:

```bash
vault secrets tune pki_int \
  -passthrough-request-headers=If-Modified-Since \
  -allowed-response-headers=Last-Modified \
  -allowed-response-headers=Location \
  -allowed-response-headers=Replay-Nonce \
  -allowed-response-headers=Link
```

> **This was the root cause** of our troubleshooting: without this tuning, Vault responded
> correctly (HTTP 200/204) but the `Replay-Nonce` header was silently filtered —
> no error, no log, just no header.

### The http-01 Challenge

ACME must prove that the requester truly controls the domain. The `http-01` challenge works:

1. Vault generates a random **token** (e.g. `3MuuQcvMXn8cV-2-QGUdh34dOoMU`)
2. The client computes the **key authorization**: `token.SHA256(accountKey)`
3. The client serves this at `http://<domain>/.well-known/acme-challenge/<token>`
4. Vault makes an HTTP request to exactly this URL and verifies the value
5. On success: Vault issues the certificate

In this demo, a temporary HTTP server is started on port 80 that answers exactly that path.
Vault reaches the container via the Docker network DNS alias `amar-demo.local`.

### Python Implementation: Vault Nonce Workaround

The standard ACME library (`acme` 5.4.0) uses `HEAD` for the `newNonce` endpoint.
Vault Enterprise only returns the `Replay-Nonce` header on `GET` — not on `HEAD`.

Therefore we override `_get_nonce` in `app/acme_client.py`:

```python
class _VaultClientNetwork(client.ClientNetwork):
    """Vault ACME only returns Replay-Nonce on GET requests, not HEAD."""

    def _get_nonce(self, url: str, new_nonce_url: str) -> None:
        if not self._nonces:
            response = self._send_request("GET", new_nonce_url)
            self._add_nonce(response)
        return self._nonces.pop()
```

---

## 3. Vault PKI Setup

The Vault configuration is fully managed via Terraform (`terraform/`).

### Certificate Chain

```
Root CA (pki mount)
  Common Name: amar-demo.local Root CA
  TTL:         87600h (10 years)
  Key:         RSA 4096

  └── Intermediate CA (pki_int mount)
        Common Name: amar-demo.local Intermediate CA
        TTL:         43800h (5 years)
        Key:         RSA 4096

        └── End-entity certificates (Role: amar-demo)
              Domain:  amar-demo.local
              TTL:     3m  (short for visible live renewal in the demo)
              Key:     RSA 2048
```

### Critical Terraform Resources

| Resource | Purpose |
|---|---|
| `vault_mount.pki_root` | Root CA mount with `allowed_response_headers` |
| `vault_mount.pki_int` | Intermediate CA mount with ACME headers |
| `vault_pki_secret_backend_root_cert.root` | Generate Root CA certificate |
| `vault_pki_secret_backend_intermediate_cert_request.int_csr` | CSR for Intermediate CA |
| `vault_pki_secret_backend_root_sign_intermediate.sign_int` | Root signs Intermediate |
| `vault_pki_secret_backend_intermediate_set_signed.set_int` | Load signed cert into mount |
| `vault_generic_endpoint.cluster_config` | `pki_int/config/cluster` — required for ACME |
| `vault_generic_endpoint.acme_config` | Enable ACME and allow role |

### Why is `cluster_config` Required?

Vault ACME needs a configured `cluster/path` to:
- Construct its own ACME directory URL
- Generate internal ACME response URLs
- Embed the `api_addr` in ACME responses

Without this entry, Vault responds with `400 Bad Request: issuer does not exist`.

---

## 4. Starting the Demo (Manual)

### Prerequisites

- Docker Desktop with an active `dev-network`
- Terraform installed
- `/etc/hosts` entry for the demo domain

### Step 1 — Check Docker network

```bash
docker network ls | grep dev-network
# If missing:
docker network create dev-network
```

### Step 2 — /etc/hosts entry

```bash
echo "127.0.0.1 amar-demo.local" | sudo tee -a /etc/hosts
```

### Step 3 — Start Vault

```bash
cd vault-acme-demo

docker run -d \
  --name vault-2.0.0 \
  --network dev-network \
  -p 8200:8200 \
  -p 8201:8201 \
  -e VAULT_LICENSE=<license-from-vault-secrets.txt> \
  -v $(pwd)/vault-config/vault.hcl:/vault/config/vault.hcl \
  -v $(pwd)/vault-data:/vault/data \
  --cap-add=IPC_LOCK \
  hashicorp/vault-enterprise:2.0-ent \
  server
```

### Step 4 — Initialize or unseal Vault

**First start (no vault-data yet):**

```bash
# Initialize
curl -s -X POST http://0.0.0.0:8200/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{"secret_shares": 1, "secret_threshold": 1}'
# Save Root Token and Unseal Key to vault-secrets.txt

# Unseal
curl -s -X POST http://0.0.0.0:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "<UNSEAL_KEY>"}'
```

**On restart (vault-data already exists):**

```bash
# Only unseal — data is preserved
curl -s -X POST http://0.0.0.0:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "<UNSEAL_KEY_FROM_VAULT_SECRETS_TXT>"}'
```

> **Note:** In production mode, Vault must be manually unsealed after every restart.
> Data in `vault-data/` is preserved.

### Step 5 — Configure Vault PKI with Terraform

```bash
cd terraform

# First start (no tfstate):
terraform init
terraform apply -var="vault_token=<ROOT_TOKEN>"

# After Vault restart (tfstate exists but is stale):
rm terraform.tfstate terraform.tfstate.backup
terraform apply -var="vault_token=<ROOT_TOKEN>"
```

### Step 6 — Start the demo microservice

```bash
cd ..
docker compose up --build
```

The service:
1. Starts HTTP server on port 80 (ACME challenge)
2. Registers ACME account with Vault
3. Performs http-01 challenge
4. Receives signed TLS certificate
5. Starts HTTPS server on port 8443

### Step 7 — Trust the Root CA on macOS (one-time)

```bash
curl -o /tmp/vault-root-ca.pem http://0.0.0.0:8200/v1/pki/ca/pem
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/vault-root-ca.pem
```

Restart your browser. `https://amar-demo.local:8443` should now show a green padlock.

### Stopping the Demo

```bash
# Stop only the demo container (Vault keeps running)
docker compose down

# Stop everything including Vault
docker compose down && docker stop vault-2.0.0

# Completely wipe Vault data (next start = full re-initialization)
docker stop vault-2.0.0 && docker rm vault-2.0.0
rm -rf vault-data/*
```

> **Note:** Vault data in `vault-data/` is preserved on normal `docker stop`. On the next start,
> Vault only needs to be unsealed. Only when `vault-data/` is deleted is a full re-initialization
> including `terraform apply` necessary.

---

## 5. Starting the Demo with an AI Assistant

You can have Claude Code (or any other AI assistant with repository and terminal access)
run the entire demo startup for you.

### Prompt for the AI Assistant

```
I want to start the Vault PKI ACME Demo. The project is located at
/Users/<your-user>/vault-acme-demo.

Please carry out the following steps:

1. Check whether the Docker network "dev-network" exists, otherwise create it.

2. Check whether the Vault container "vault-2.0.0" is already running.
   - If not: start it with the command from the README (step 3).
     The VAULT_LICENSE value can be found in vault-secrets.txt.

3. Check whether Vault is already initialized and unsealed:
   curl http://0.0.0.0:8200/v1/sys/health
   - initialized: false → initialize (step 4, first start)
   - sealed: true → only unseal (unseal key from vault-secrets.txt)
   - initialized: true, sealed: false → continue with step 5

4. Check whether the Terraform state exists (terraform/terraform.tfstate).
   - Does not exist or Vault was restarted → terraform apply
     with the root token from vault-secrets.txt

5. Start the demo container:
   docker compose up --build -d

6. Show me the logs until the certificate has been issued:
   docker logs vault-acme-demo -f

7. Test the endpoint:
   curl -sk --resolve "amar-demo.local:8443:127.0.0.1" https://amar-demo.local:8443/
```

### What the AI Assistant Must Keep in Mind

- **tfstate and Vault restart:** The Terraform state references Vault-internal issuer UUIDs.
  After a Vault restart these IDs are gone, so `terraform.tfstate` must be deleted and
  `terraform apply` re-run.

- **Mount tuning:** The `allowed_response_headers` mount tuning is already in `main.tf`
  and is applied automatically during `terraform apply`.

- **Port 80:** The demo container needs port 80 for the ACME challenge.
  If another process occupies port 80, the challenge will fail.

---

## 6. Testing the Endpoints

```bash
# Health check + certificate info
curl -sk --resolve "amar-demo.local:8443:127.0.0.1" \
  https://amar-demo.local:8443/ | python3 -m json.tool

# Full certificate details
curl -sk --resolve "amar-demo.local:8443:127.0.0.1" \
  https://amar-demo.local:8443/cert | python3 -m json.tool

# Verify with Root CA
curl -s http://0.0.0.0:8200/v1/pki/ca/pem -o /tmp/ca.pem
curl --cacert /tmp/ca.pem https://amar-demo.local:8443/

# Vault UI
open http://localhost:8200/ui
# Token: see vault-secrets.txt

# ACME directory
curl -s http://0.0.0.0:8200/v1/pki_int/roles/amar-demo/acme/directory | python3 -m json.tool

# Fetch a new nonce (should show Replay-Nonce header)
curl -sI http://0.0.0.0:8200/v1/pki_int/roles/amar-demo/acme/new-nonce
```

### Endpoints Overview

| Endpoint | Format | Description |
|---|---|---|
| `GET /` | HTML | Web UI with live countdown and renewal log |
| `GET /cert` | JSON | Certificate details as machine-readable JSON |

### Expected Response from `GET /cert`

```json
{
  "subject": "CN=amar-demo.local",
  "issuer": "CN=amar-demo.local Intermediate CA,OU=Platform,O=Amar Demo Org,C=DE",
  "serial_number": "0x2608da5335f005ae6347aecb3d223597ec5aa88e",
  "not_before": "2026-03-20T21:29:31+00:00",
  "not_after":  "2026-03-20T21:32:31+00:00",
  "expires_in_seconds": 142,
  "expires_in_hours": 0.0395,
  "expires_in_days": 0.0016,
  "total_ttl_seconds": 180,
  "sans": ["amar-demo.local"],
  "valid": true
}
```

---

## 7. Live Demo: Automatic Certificate Renewal

> **Note — Demo setup:** This setup with Python/FastAPI and Uvicorn is intended exclusively for
> demo and learning purposes to make the ACME protocol flow visible. In production you would use
> a web server like **nginx** that performs a zero-downtime hot-reload with `nginx -s reload`
> after certificate renewal — no process restart, no interrupted connections.
> Uvicorn must be restarted (~1-2s downtime), which is acceptable for a demo but not for
> production.

The demo is configured so that the entire ACME renewal cycle can be observed live in under
3 minutes — in the browser and in the container logs.

### Configuration

```
Certificate TTL:  3m   (terraform/variables.tf → cert_ttl)
Renew when:      < 60s remaining
Check interval:   30s
```

### What Happens in the Background

```
T+0:00   Certificate issued (178s lifetime)
T+0:30   [renewal] Check → 148s remaining (threshold: 60s)
T+1:00   [renewal] Check → 118s remaining (threshold: 60s)
T+1:30   [renewal] Check → 88s remaining (threshold: 60s)
T+2:00   [renewal] Check → 58s remaining  <-- Threshold reached!
T+2:00   [renewal] *** ACME Renewal started ***
T+2:03   [renewal] New certificate — new serial, 178s valid
T+2:03   [server]  HTTPS server restarted with new certificate
T+2:33   [renewal] Check → 148s remaining (next cycle)
```

### Live Log Monitoring (for customer demos)

```bash
docker logs vault-acme-demo -f
```

Relevant log lines during the demo:

```
[renewal] Certificate check — 58s remaining (threshold: 60s)
[renewal] *** Threshold reached (58s < 60s) — starting ACME renewal ***
[renewal] New certificate obtained — serial 0x781eea..., valid for 178s
[renewal] Signalling HTTPS server to reload with new certificate...
[server]  Restarting HTTPS server with renewed certificate...
[server]  Starting HTTPS server on https://amar-demo.local:8443
```

### Web UI — Live Countdown in the Browser

Open `https://amar-demo.local:8443` for the dashboard:

- **Large countdown timer** — shows remaining lifetime in MM:SS
  - Green: > 3x threshold (normal)
  - Orange: between 1x and 3x threshold (expiring soon)
  - Red + blinking: below threshold (renewal about to trigger)
  - Purple pulsing: certificate expired / renewal in progress
- **Validity bar** — depleting progress bar shows certificate lifetime consumed
- **Renewal counter** — number of renewals that have taken place
- **Renewal activity log** — timestamp of each renewal with new serial number
- **Auto-refresh** — page reloads every 5 seconds

### Why Not nginx? — Demo vs. Production

| | This Demo (Python/Uvicorn) | Production Setup (nginx) |
|---|---|---|
| **Purpose** | Visualize the ACME flow | TLS termination in operation |
| **After renewal** | Stop + restart Uvicorn | `nginx -s reload` (HUP signal) |
| **Downtime** | ~1-2 seconds | 0 seconds (zero-downtime) |
| **Active connections** | Interrupted | Handled gracefully to completion |
| **Mechanism** | Process restart | Hot-reload — only workers swap |
| **Visible in logs?** | Yes — every step logged | Barely — runs silently |

nginx supports graceful reload: the master process stays alive, new workers load the new
certificate, old workers finish active requests cleanly. Tools like **Certbot** use this:

```bash
certbot renew --deploy-hook "nginx -s reload"
```

### Adjusting Certificate TTL for Production

In `terraform/variables.tf`:

```hcl
variable "cert_ttl" {
  default = "720h"   # 30 days — typical for production PKI
}
```

And in `docker-compose.yml`:

```yaml
- RENEW_SECONDS=86400   # renew 24h before expiry
- CHECK_INTERVAL=3600   # check hourly
```

---

## 8. Troubleshooting

### `acme.errors.MissingNonce` — no Replay-Nonce header

```bash
# Check whether the header is present
curl -sI http://0.0.0.0:8200/v1/pki_int/roles/amar-demo/acme/new-nonce | grep -i replay

# If not → check mount tuning
curl -s -H "X-Vault-Token: <TOKEN>" \
  http://0.0.0.0:8200/v1/sys/mounts/pki_int/tune | python3 -m json.tool | grep -A5 "allowed_response"

# Fix: re-apply mount tuning
curl -X POST http://0.0.0.0:8200/v1/sys/mounts/pki_int/tune \
  -H "X-Vault-Token: <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"passthrough_request_headers":["If-Modified-Since"],
       "allowed_response_headers":["Last-Modified","Location","Replay-Nonce","Link"]}'
```

> **Docs:** [Mount Tune API](https://developer.hashicorp.com/vault/api-docs/system/mounts) · [PKI ACME](https://developer.hashicorp.com/vault/docs/secrets/pki/acme)

### `issuer does not exist` — 400 on ACME endpoints

Terraform state is stale (Vault was restarted, old issuer UUIDs in state):

```bash
cd terraform
rm terraform.tfstate terraform.tfstate.backup
# Delete PKI mounts from Vault if they exist:
curl -X DELETE -H "X-Vault-Token: <TOKEN>" http://0.0.0.0:8200/v1/sys/mounts/pki
curl -X DELETE -H "X-Vault-Token: <TOKEN>" http://0.0.0.0:8200/v1/sys/mounts/pki_int
terraform apply -var="vault_token=<TOKEN>"
```

### Vault sealed after restart

```bash
curl -s http://0.0.0.0:8200/v1/sys/health | python3 -c "import sys,json; print(json.load(sys.stdin)['sealed'])"
# true → unseal:
curl -X POST http://0.0.0.0:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "<UNSEAL_KEY_FROM_VAULT_SECRETS_TXT>"}'
```

### ACME challenge fails

```bash
# Can Vault reach the demo container on port 80?
docker exec vault-2.0.0 wget -q -O- http://amar-demo.local/.well-known/acme-challenge/test

# Is the container in the correct network?
docker inspect vault-acme-demo --format '{{json .NetworkSettings.Networks}}' | python3 -m json.tool
# Must contain "dev-network" with alias "amar-demo.local"
```

### Browser shows "Not Secure" after Vault restart

The Root CA fingerprint in the Keychain no longer matches the current Vault CA. Run `./deploy.sh`
— it compares fingerprints and updates the trust store automatically.

Or manually:

```bash
# Remove old certificate from Keychain
sudo security delete-certificate -c "amar-demo.local Root CA" /Library/Keychains/System.keychain

# Add the new Root CA
curl -o /tmp/vault-root-ca.pem http://0.0.0.0:8200/v1/pki/ca/pem
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/vault-root-ca.pem

# Also update LibreSSL (used by curl on macOS)
sudo bash -c "cat /tmp/vault-root-ca.pem >> /etc/ssl/cert.pem"
```

### `invalid, non-URL path given to cluster`

Vault 2.0.0 rejects hostnames like `vault-2.0.0` in the PKI cluster config URL validator.
`deploy.sh` automatically uses the container IP from `docker inspect` and passes it as
`vault_docker_ip` to Terraform.

---

## 9. Project Structure

```
vault-acme-demo/
├── app/
│   ├── acme_client.py       # ACME flow (http-01 challenge, Vault nonce workaround)
│   ├── main.py              # FastAPI HTTPS server + renewal loop
│   └── requirements.txt     # Python dependencies
│
├── scripts/
│   ├── security-check.sh      # Pre-commit hook: blocks secrets from being committed
│   ├── security-scan-repo.sh  # CI scanner: all tracked files + full git history
│   └── code-audit.sh          # Bi-weekly audit: bandit · pip-audit · checkov
│
├── terraform/
│   ├── main.tf              # PKI Root CA, Intermediate CA, ACME config
│   ├── variables.tf         # vault_addr, vault_token, domain, cert_ttl, vault_docker_ip
│   ├── outputs.tf           # ACME directory URL, CA URLs, service URL
│   └── provider.tf          # Terraform version + Vault provider (hashicorp/vault ~> 4.0)
│
├── vault-config/
│   └── vault.hcl            # Vault production config (Raft, TLS disabled, UI)
│
├── vault-data/              # Raft storage volume (persistent) — gitignored
│
├── .github/
│   └── workflows/
│       └── security-scan.yml  # Security Engineer Agent (secret scan + code audit)
│
├── .gitignore               # Protects secrets, vault-data, tfstate, certs
├── deploy.sh                # One-command deployment (Vault + Terraform + Docker + CA trust)
├── docker-compose.yml       # Demo microservice (dev-network, amar-demo.local alias)
├── Dockerfile               # Python 3.11 slim, port 80 + 8443
├── vault-secrets.example.txt  # Credentials template (vault-secrets.txt is gitignored)
├── README.md                # English quick-start (GitHub landing page)
├── README.en.md             # This file — full English in-depth guide
└── README.de.md             # Full German in-depth guide
```

> **Note:** `vault-secrets.txt` (root token, unseal key, license) is in `.gitignore` and is
> never committed. Copy `vault-secrets.example.txt` to `vault-secrets.txt` and fill in your values.

### Environment Variables (`docker-compose.yml`)

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | `http://vault-2.0.0:8200` | Vault address (Docker DNS) |
| `PKI_MOUNT` | `pki_int` | PKI secrets engine mount |
| `PKI_ROLE` | `amar-demo` | PKI role for certificate issuance |
| `DOMAIN` | `amar-demo.local` | Certificate domain |
| `HTTPS_PORT` | `8443` | HTTPS port of the microservice |
| `RENEW_SECONDS` | `60` | Seconds before expiry to trigger renewal |
| `CHECK_INTERVAL` | `30` | Renewal check interval in seconds |

### Security Architecture

Three independent layers of automated security scanning:

| Layer | Script | Trigger | What it checks |
|---|---|---|---|
| Pre-commit | `scripts/security-check.sh` | Every `git commit` | Staged diff: tokens, keys, blocked files |
| CI scan | `scripts/security-scan-repo.sh` | Every push/PR + weekly | All tracked files + full git history |
| Code audit | `scripts/code-audit.sh` | Bi-weekly + manual | Python SAST · dependency CVEs · IaC policies |

A PR is opened **only on CRITICAL or HIGH findings**. The security branch is deleted automatically
after a clean audit.
