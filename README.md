# Vault PKI ACME Demo

A Python microservice that automatically obtains and renews TLS certificates from HashiCorp Vault using the ACME protocol (http-01 challenge). Built for demonstrating zero-touch certificate management.

> **German documentation:** See [README.de.md](README.de.md) for the full in-depth guide including architecture diagrams, ACME protocol walkthrough, and troubleshooting.

---

## Architecture

```
Mac Host
├── vault-2.0.0 (Port 8200/8201)  — Vault Enterprise, PKI + ACME Endpoint
│     ├── pki      → Root CA (RSA 4096, 10y)
│     └── pki_int  → Intermediate CA + ACME enabled (RSA 4096, 5y)
└── vault-acme-demo (Port 80/8443) — Python Microservice
      ├── :80   ACME http-01 challenge server (temporary)
      └── :8443 FastAPI HTTPS  GET /  (Web UI)  GET /cert  (JSON)

Docker Network: dev-network
  vault-2.0.0    → DNS name for Vault container
  amar-demo.local → DNS alias for the demo container (ACME challenge)
```

**Stack:** Python 3.11 · FastAPI · Vault Enterprise 2.0.0-ent · Terraform · Docker Compose

---

## Quick Start

```bash
git clone https://github.com/lomar92/vault-acme-demo.git
cd vault-acme-demo

# Copy credentials template and fill in your values
cp vault-secrets.example.txt vault-secrets.txt
# Edit vault-secrets.txt with your Root Token, Unseal Key, and License

# Deploy everything in one command
./deploy.sh
```

`deploy.sh` handles the full lifecycle automatically:
1. Creates `dev-network` if missing
2. Starts `vault-2.0.0` container (run / start / skip based on current state)
3. Unseals Vault (reads credentials from `vault-secrets.txt`)
4. Clears stale tfstate + PKI mounts if Vault was restarted, then runs `terraform apply`
5. Builds and starts `vault-acme-demo` container
6. Adds Root CA to macOS Keychain + LibreSSL CA bundle (fingerprint check — sudo only when needed)

After deploy: open `https://amar-demo.local:8443` — no browser warning.

---

## How It Works

ACME (RFC 8555) is the protocol behind Let's Encrypt. Vault implements the same standard as an internal CA. The microservice:

1. Fetches the ACME directory from Vault
2. Registers an ACME account
3. Requests a certificate for `amar-demo.local`
4. Proves domain control via http-01 challenge (serves a token on port 80)
5. Receives a signed certificate from Vault's Intermediate CA
6. Starts HTTPS on port 8443
7. Background thread renews the certificate when < 60s remain (3-minute TTL for visible renewal in the demo)

---

## Project Structure

```
vault-acme-demo/
├── app/
│   ├── acme_client.py       # ACME http-01 flow + Vault nonce workaround
│   ├── main.py              # FastAPI HTTPS server + renewal loop
│   └── requirements.txt
├── scripts/
│   ├── security-check.sh   # Pre-commit hook: blocks secrets from being committed
│   └── security-scan-repo.sh  # Full repo scanner (runs in GitHub Actions)
├── terraform/
│   ├── main.tf              # PKI hierarchy + ACME config
│   ├── variables.tf         # vault_addr, vault_token, domain, cert_ttl, vault_docker_ip
│   ├── outputs.tf
│   └── provider.tf
├── vault-config/vault.hcl   # Vault server config (Raft, port 8200, TLS off)
├── vault-data/              # Raft persistent storage — gitignored
├── .gitignore               # Protects secrets, vault-data, tfstate, certs
├── deploy.sh                # One-command deploy
├── docker-compose.yml
├── Dockerfile
├── vault-secrets.example.txt  # Credentials template (vault-secrets.txt is gitignored)
├── README.md                # This file (English)
└── README.de.md             # Full German documentation
```

---

## PKI Hierarchy

```
Root CA (pki)          RSA 4096 — never signs end certificates directly
  └── Intermediate CA (pki_int)  RSA 4096 — ACME enabled
        └── Role: amar-demo      RSA 2048, TTL 3m (short for visible renewal)
```

---

## Testing

```bash
# Certificate info (no -k needed after deploy.sh adds Root CA to trust store)
curl -s https://amar-demo.local:8443/cert | python3 -m json.tool

# Watch live renewal in logs
docker logs -f vault-acme-demo

# Vault UI
open http://localhost:8200/ui
```

---

## Security

This repo has an automated **Security Engineer Agent** (GitHub Actions):

| Trigger | What runs |
|---|---|
| Every push to `main` | Secret scan (tokens, private keys, licenses) |
| Weekly (Mon 08:00 UTC) | Secret scan + git history scan |
| Bi-weekly (1st + 15th) | Full code audit: bandit · pip-audit · checkov |
| Manual (`workflow_dispatch`) | Both scans |

A PR is opened **only when CRITICAL or HIGH findings** are detected. The security branch is deleted automatically after a clean audit.

The pre-commit hook (`scripts/security-check.sh`) runs locally before every commit and blocks:
- Vault tokens (`hvs.` / `hvb.` prefix)
- Private key headers
- Vault Enterprise licenses
- Unseal keys
- `.pem` / `.key` files

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VAULT_ADDR` | `http://vault-2.0.0:8200` | Vault address (Docker DNS) |
| `PKI_MOUNT` | `pki_int` | PKI secrets engine mount |
| `PKI_ROLE` | `amar-demo` | PKI role for certificate issuance |
| `DOMAIN` | `amar-demo.local` | Certificate domain |
| `HTTPS_PORT` | `8443` | HTTPS port |
| `RENEW_SECONDS` | `60` | Seconds before expiry to trigger renewal |
| `CHECK_INTERVAL` | `30` | Renewal check interval in seconds |

---

## Known Issues

**`invalid, non-URL path given to cluster`** — Vault 2.0.0 rejects hostnames like `vault-2.0.0` in the PKI cluster config URL validator. `deploy.sh` automatically uses the container's IP address via `docker inspect` and passes it as `vault_docker_ip` to Terraform.

**`issuer does not exist`** — Vault was restarted, making tfstate issuer UUIDs stale. `deploy.sh` detects this and clears tfstate + PKI mounts automatically before re-applying.

**Browser shows "Not Secure"** — Root CA fingerprint in Keychain doesn't match current Vault CA (happens after Vault restart + fresh PKI). Run `./deploy.sh` — it compares fingerprints and updates the trust store automatically.
