# ai-demo — CLAUDE.md

Jede neue Claude-Session liest diese Datei automatisch. Damit verstehst du das Projekt sofort — ohne alle Dateien neu durchsuchen zu müssen.

---

## 1. Was ist dieses Projekt?

Dieses Projekt demonstriert **automatische TLS-Zertifikate via ACME** — ohne manuelles Zertifikats-Management.

Ein Python-Microservice (FastAPI) holt sich beim Start selbständig ein TLS-Zertifikat von HashiCorp Vault und erneuert es automatisch im Hintergrund, bevor es abläuft. Das ist nützlich, weil in der Praxis manuelle Zertifikatsverwaltung fehleranfällig ist und häufig zu ungeplanten Ausfällen führt.

**Stack:** Python 3.11 · FastAPI · Vault Enterprise 2.0.0-ent · Terraform · Docker Compose

---

## 2. Was ist ACME? (Kurzerklärung für Einsteiger)

**ACME** = Automatic Certificate Management Environment ([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555))

Let's Encrypt hat dieses Protokoll entwickelt, damit Webserver kostenlos und vollautomatisch TLS-Zertifikate bekommen können. HashiCorp Vault implementiert denselben ACME-Standard — damit kann Vault als interne CA für automatische Zertifikate genutzt werden.

**http-01 Challenge in 3 Sätzen:** Der ACME-Server (Vault) stellt eine Aufgabe: "Beweise, dass du diese Domain kontrollierst." Der Client (unser Microservice) legt eine temporäre Datei unter `/.well-known/acme-challenge/<token>` auf Port 80 ab. Vault ruft diese URL ab — wenn sie erreichbar ist und den richtigen Inhalt hat, wird das Zertifikat ausgestellt.

---

## 3. Architektur

```
Mac Host
├── vault-2.0.0 (Port 8200/8201) — Vault Enterprise, PKI + ACME Endpoint
│     ├── pki      → Root CA
│     └── pki_int  → Intermediate CA + ACME aktiviert
└── vault-acme-demo (Port 80/8443) — Python Microservice
      ├── :80   ACME Challenge Server (temporär, nur bei Cert-Request)
      └── :8443 FastAPI HTTPS — GET / (Web UI), GET /cert (JSON)

Docker Netzwerk: dev-network
  vault-2.0.0 → DNS-Name für Vault
  amar-demo.local  → DNS-Alias für den Demo-Container
```

---

## 4. Projektstruktur

```
ai-demo/
├── app/
│   ├── acme_client.py   # ACME http-01 Flow
│   ├── main.py          # FastAPI HTTPS-Server + Background Renewal Loop
│   └── requirements.txt
├── terraform/
│   ├── main.tf          # Vault PKI: Root CA → Intermediate CA → Role → ACME Config
│   ├── variables.tf     # vault_addr, vault_token, domain, cert_ttl, vault_docker_ip
│   ├── outputs.tf       # Nützliche URLs nach terraform apply
│   └── provider.tf      # Terraform-Version + Vault Provider (hashicorp/vault ~> 4.0)
├── vault-config/vault.hcl    # Vault Server: Raft Storage, Port 8200, TLS off
├── vault-data/               # Raft Persistent Storage (Volume)
├── deploy.sh                 # Einzel-Befehl-Deployment (Vault + Terraform + Docker + CA-Trust)
├── docker-compose.yml        # Demo Microservice Definition
├── Dockerfile                # Python 3.11-slim, Port 80 + 8443
├── vault-secrets.txt         # Root Token, Unseal Key, Enterprise License
└── README.md                 # Vollständige Dokumentation (Deutsch)
```

---

## 5. Vault PKI-Hierarchie

**Warum Root CA → Intermediate CA → Zertifikat?**
Sicherheit durch Trennung: Der Root CA Private Key bleibt isoliert und wird nie direkt für End-Zertifikate verwendet. Wird die Intermediate CA kompromittiert, kann sie widerrufen werden, ohne die Root CA neu aufzusetzen.

```
Root CA (pki)
  — RSA 4096, 10 Jahre
  — niemals direkt für End-Zertifikate verwendet
  └── Intermediate CA (pki_int)
        — RSA 4096, 5 Jahre
        — signiert End-Zertifikate, hat ACME aktiviert
        └── Role: amar-demo
              — RSA 2048, TTL: 3m
              — (kurze TTL für sichtbares Auto-Renewal in der Demo)
```

---

## 6. Key Functions

| Funktion | Datei | Zweck |
|---|---|---|
| `obtain_certificate()` | `app/acme_client.py` | Vollständiger ACME http-01 Flow: Account → Order → Challenge → Cert |
| `_renewal_loop()` | `app/main.py` | Background-Thread: prüft Ablauf alle 30s, erneuert bei Bedarf |
| `_parse_cert()` | `app/main.py` | Extrahiert Metadaten (Ablauf, SANs) aus PEM-Zertifikat |
| `main()` | `app/main.py` | Startup: ACME → uvicorn HTTPS starten → Renewal Loop |

---

## 7. Umgebungsvariablen

| Variable | Default | Beschreibung |
|---|---|---|
| `VAULT_ADDR` | `http://vault-2.0.0:8200` | Vault Adresse (Docker DNS) |
| `PKI_MOUNT` | `pki_int` | PKI Secrets Engine Mount |
| `PKI_ROLE` | `amar-demo` | PKI Role für Zertifikats-Ausstellung |
| `DOMAIN` | `amar-demo.local` | Domain des Zertifikats |
| `HTTPS_PORT` | `8443` | HTTPS Port des Microservice |
| `RENEW_SECONDS` | `60` | Sekunden vor Ablauf für Auto-Renewal |
| `CHECK_INTERVAL` | `30` | Prüfintervall in Sekunden |

---

## 8. Demo starten

### Empfohlen — deploy.sh (ein Befehl)

```bash
./deploy.sh
```

Das Script erledigt alles vollautomatisch:
1. Docker-Netzwerk `dev-network` prüfen / anlegen
2. `vault-2.0.0` Container starten (run/start/skip je nach Zustand)
3. Vault entsiegeln (Credentials aus `vault-secrets.txt`)
4. Veralteten tfstate + PKI Mounts aufräumen, Terraform apply
5. `vault-acme-demo` Container bauen + starten
6. Root CA Trust prüfen — nur wenn nötig (Fingerprint-Vergleich + curl-Test):
   - Fingerprint von Vault-Root-CA vs. macOS Keychain vergleichen
   - End-to-End-Test: `curl` ohne `-k` gegen `https://amar-demo.local:8443/cert`
   - Nur wenn beides fehlschlägt → sudo (Keychain + LibreSSL CA-Bundle)
   - Bereits korrekt vertraut → Schritt wird übersprungen, kein sudo

Nach dem Deploy: `https://amar-demo.local:8443` öffnet ohne Browser-Warnung.

---

### Via Claude / Agent

Sage: **"Starte die Demo"** oder **"deploy"**

Claude führt `./deploy.sh` aus. Der sudo-Prompt erscheint nur wenn der CA-Trust veraltet ist oder fehlt.

**Wichtig für Agents:** Das Script ist idempotent — mehrfach ausführbar. Bei Vault-Neustart räumt es tfstate + PKI Mounts automatisch auf.

---

### Manuell (Fallback)

```bash
# 1. Vault starten + entsiegeln
docker start vault-2.0.0
curl -s -X POST http://0.0.0.0:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "<UNSEAL_KEY aus vault-secrets.txt>"}'

# 2. Terraform
cd terraform
rm -f terraform.tfstate terraform.tfstate.backup   # bei Vault-Neustart!
VAULT_IP=$(docker inspect vault-2.0.0 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
terraform init && terraform apply \
  -var="vault_token=<ROOT_TOKEN>" \
  -var="vault_docker_ip=$VAULT_IP"

# 3. Demo Container + CA-Trust
cd ..
docker compose up --build -d
curl -s http://localhost:8200/v1/pki/ca/pem -o /tmp/vault-root-ca.pem
sudo security delete-certificate -c "amar-demo.local Root CA" \
  /Library/Keychains/System.keychain 2>/dev/null || true
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/vault-root-ca.pem
sudo bash -c 'cat /tmp/vault-root-ca.pem >> /etc/ssl/cert.pem'

# 4. Testen
curl -s https://amar-demo.local:8443/cert | python3 -m json.tool
```

---

## 9. Häufigste Fehler

**`issuer does not exist` (HTTP 400 auf ACME Endpoints)**
Vault wurde neu gestartet — die Issuer-UUIDs im tfstate sind veraltet.
→ `./deploy.sh` erkennt das automatisch und räumt auf. Manuell: tfstate löschen + PKI Mounts via API löschen + `terraform apply`.

**`invalid, non-URL path given to cluster: http://vault-2.0.0:8200/...`**
Vault 2.0.0 lehnt Hostnamen mit Punkt-Ziffern-Mustern (wie `vault-2.0.0`) im PKI cluster config URL-Validator ab.
→ `deploy.sh` ermittelt die Container-IP automatisch per `docker inspect` und übergibt sie als `vault_docker_ip` Variable an Terraform. Nicht `vault-2.0.0` als Hostname verwenden.

**`acme.errors.MissingNonce`**
Der `Replay-Nonce` Header fehlt im Mount-Tuning von `pki_int`.
→ `terraform apply` setzt `allowed_response_headers` automatisch korrekt.

**ACME Challenge schlägt fehl**
→ Port 80 belegt, oder Container ist nicht im `dev-network` mit Alias `amar-demo.local`.
```bash
docker inspect vault-acme-demo --format '{{json .NetworkSettings.Networks}}' | python3 -m json.tool
```

**Browser zeigt "Nicht sicher" trotz HTTPS**
→ Root CA noch nicht im macOS Keychain. `./deploy.sh` macht das automatisch als letzten Schritt.

---

## 10. Vollständige Dokumentation

→ **README.md** (Deutsch) — Details, Architektur-Diagramme, Troubleshooting, Demo vs. Produktion
