# Vault PKI ACME Demo

Eine vollständige Demo, die zeigt wie ein Python-Microservice sein TLS-Zertifikat
automatisch von HashiCorp Vault über das ACME-Protokoll (http-01 Challenge) bezieht.

---

## Inhaltsverzeichnis

1. [Architektur](#1-architektur)
2. [Technischer Hintergrund: ACME & Nonces](#2-technischer-hintergrund-acme--nonces)
3. [Vault PKI Aufbau](#3-vault-pki-aufbau)
4. [Demo starten (manuell)](#4-demo-starten-manuell)
5. [Demo starten mit einem AI Assistenten](#5-demo-starten-mit-einem-ai-assistenten)
6. [Endpoints testen](#6-endpoints-testen)
7. [Live-Demo: Automatische Zertifikats-Erneuerung](#7-live-demo-automatische-zertifikats-erneuerung)
8. [Troubleshooting](#8-troubleshooting)
9. [Projektstruktur](#9-projektstruktur)

---

## 1. Architektur

```
Mac Host
├── Vault Enterprise (Docker)
│   ├── Container:  vault-2.0.0
│   ├── Port:       8200 (HTTP API + UI)
│   ├── Port:       8201 (Raft Cluster)
│   ├── Storage:    Raft (vault-data/ Volume)
│   └── PKI Engine
│         ├── pki       → Root CA
│         └── pki_int   → Intermediate CA + ACME Endpoint
│
└── Python Microservice (Docker)
      ├── Container:  vault-acme-demo
      ├── Port 80:    ACME http-01 Challenge Server (temporär)
      └── Port 8443:  HTTPS API (FastAPI)
            GET /      → Health + Zertifikat-Info
            GET /cert  → Vollständige Zertifikat-Details

Docker Netzwerk: dev-network
  vault-2.0.0  → DNS-Name für den Vault Container
  amar-demo.local   → DNS-Alias für den Demo-Container (für ACME Challenge)
```

### ACME Flow im Überblick

```
Demo Container                    Vault (ACME)
     │                                │
     │  GET /acme/directory           │
     │ ──────────────────────────────>│
     │ <── directory URLs ────────────│
     │                                │
     │  HEAD /acme/new-nonce          │
     │ ──────────────────────────────>│
     │ <── Replay-Nonce: abc123 ──────│
     │                                │
     │  POST /acme/new-account        │
     │ ──────────────────────────────>│
     │ <── account URL ───────────────│
     │                                │
     │  POST /acme/new-order          │
     │ ──────────────────────────────>│
     │ <── order + auth URLs ─────────│
     │                                │
     │  [Challenge Server Port 80]    │
     │  POST /acme/challenge          │
     │ ──────────────────────────────>│
     │              Vault validiert:  │
     │         GET /.well-known/...   │
     │ <──────────────────────────────│
     │ (Challenge Server antwortet)   │
     │ ─────────────────────────────> │
     │                                │
     │  POST /acme/order/finalize     │
     │ ──────────────────────────────>│
     │ <── fullchain.pem ─────────────│
     │                                │
     │  [HTTPS Server Port 8443]      │
     │  startet mit neuem Zertifikat  │
```

### ACME Flow — Schritt für Schritt erklärt

Stell dir ACME wie einen automatisierten Schalter vor, an dem dein Service
ein offizielles TLS-Zertifikat abholt — vollautomatisch, ohne dass ein Mensch
eingreifen muss. Der Ablauf hat fünf logische Schritte.

---

#### Schritt 1: Wo finde ich dich? — Das Telefonbuch

Bevor der Service irgendetwas tun kann, fragt er Vault:
**"An welche Adressen muss ich mich wenden?"**

Vault antwortet mit einem Telefonbuch — einer Liste aller URLs, die für den
weiteren Ablauf gebraucht werden: Wo registriere ich mich? Wo stelle ich eine
Anfrage? Wo hole ich den Einmalcode ab?

> Das ist wichtig, weil der Service diese Adressen nicht kennen darf —
> der ACME-Standard schreibt vor, dass der Server sie immer frisch liefert.
> So kann Vault seine internen URLs jederzeit ändern, ohne dass der Client
> angepasst werden muss.

---

#### Schritt 2: Beweise, dass du kein Angreifer bist — Der Einmalcode (Nonce)

Jede Nachricht, die der Service an Vault schickt, muss einen **Einmalcode**
enthalten — die sogenannte **Nonce**.

**Warum?** Stell dir vor, jemand belauscht die Kommunikation und zeichnet
eine gültige Zertifikatsanfrage auf. Ohne Einmalcode könnte er diese Anfrage
einfach erneut abspielen und sich ein weiteres Zertifikat ausstellen lassen.

Mit der Nonce geht das nicht: Vault gibt einen Code aus, der **genau einmal**
verwendet werden darf. Danach ist er wertlos. Nach jeder Antwort liefert Vault
automatisch einen neuen Code für den nächsten Schritt — der Service muss nie
darum bitten.

> **In dieser Demo:** Genau hier lag der Troubleshooting-Aufwand.
> Vault hat den Einmalcode intern generiert, ihn aber nicht in der Antwort
> mitgeschickt — weil ein Sicherheitsfilter ihn blockiert hat.
> Fix: Den Header `Replay-Nonce` explizit als erlaubt markieren.

---

#### Schritt 3: Wer bist du? — Die Registrierung

Der Service erstellt ein **Schlüsselpaar** (wie ein digitaler Ausweis) und
registriert sich damit bei Vault. Von diesem Moment an signiert er alle
seine Nachrichten mit diesem Schlüssel.

Vault weiß dadurch: Diese Anfragen kommen wirklich von diesem Service —
und nicht von jemandem der sich als dieser Service ausgibt.

> Dieser Schlüssel hat nichts mit dem späteren TLS-Zertifikat zu tun.
> Er ist nur für die Kommunikation mit Vault während des ACME-Prozesses.

---

#### Schritt 4: Beweise, dass die Domain dir gehört — Die Challenge

Das ist der eigentliche Kernpunkt von ACME.

Vault sagt: **"Du willst ein Zertifikat für `amar-demo.local` — beweise,
dass du diese Domain kontrollierst."**

So funktioniert der Beweis (`http-01 Challenge`):

```
1. Vault gibt einen zufälligen Code aus, z. B.:  3MuuQcvMXn8cV-2-QGUdh34dOoMU

2. Der Service stellt diesen Code auf Port 80 der Domain bereit:
   http://amar-demo.local/.well-known/acme-challenge/3MuuQcvMXn8cV-2-QGUdh34dOoMU

3. Der Service sagt Vault: "Ich bin bereit, schau nach."

4. Vault ruft diese URL selbst ab und prüft ob der Code stimmt.

5. Stimmt er → Domain-Kontrolle bewiesen → Vault stellt das Zertifikat aus.
```

> **Warum ist das sicher?** Nur wer wirklich die Domain kontrolliert,
> kann auf Port 80 antworten. Ein Angreifer könnte zwar die Anfrage
> mitlesen — aber er kann nicht auf der Domain antworten.
>
> In dieser Demo lauscht der Python-Service kurz auf Port 80 und
> antwortet auf genau diese eine URL. Vault erreicht ihn über den
> Docker-Netzwerk-Namen `amar-demo.local`.

---

#### Schritt 5: Das Zertifikat abholen

Nachdem die Domain-Kontrolle bewiesen ist, schickt der Service eine
**Zertifikatsanfrage (CSR)** an Vault. Darin steht:

- Für welche Domain das Zertifikat ausgestellt werden soll
- Der öffentliche Schlüssel, der ins Zertifikat eingebettet werden soll

Vault's Intermediate CA unterschreibt das Zertifikat und schickt es zurück.
Der Service speichert es als `cert.pem` zusammen mit dem privaten Schlüssel
als `key.pem` und startet dann den HTTPS-Server damit.

---

#### Die zwei Schlüssel — eine häufige Verwechslung

In diesem Prozess gibt es **zwei verschiedene Schlüsselpaare**, die nichts
miteinander zu tun haben:

| | Account Key | Domain Key |
|---|---|---|
| **Zweck** | Kommunikation mit Vault | Das TLS-Zertifikat selbst |
| **Wer sieht ihn?** | Nur Vault | Jeder Browser der die HTTPS-Verbindung aufbaut |
| **Lebensdauer** | Nur während ACME | Solange das Zertifikat gültig ist |
| **Im Zertifikat?** | Nein | Ja |

> Vereinfacht: Der Account Key ist der Ausweis beim Schalter.
> Der Domain Key ist der Schlüssel für das Schloss an der Haustür.

---

## 2. Technischer Hintergrund: ACME & Nonces

### Was ist ACME?

ACME (Automatic Certificate Management Environment) ist ein Protokoll (RFC 8555),
das die automatische Ausstellung und Erneuerung von TLS-Zertifikaten standardisiert.
Let's Encrypt nutzt ACME — HashiCorp Vault implementiert es ebenfalls in der PKI Engine.

### Warum gibt es Nonces?

ACME-Requests sind signierte JSON-Objekte (JWS — JSON Web Signature). Ohne einen
Anti-Replay-Mechanismus könnte ein Angreifer einen alten, gültigen Request erneut
absenden und damit unerwünschte Aktionen auslösen (z. B. ein Zertifikat erneut
ausstellen oder widerrufen).

**Eine Nonce (Number used once) ist ein einmaliger, zufälliger Wert**, den der
Server ausgibt. Der Client muss diesen Wert in jeden signierten Request einbetten.
Der Server akzeptiert jeden Nonce-Wert nur genau einmal.

### Der Nonce-Mechanismus im Detail (RFC 8555 §6.5 & §7.2)

#### Schritt 1 — Nonce abrufen

Der Client macht einen `HEAD` (oder `GET`) Request auf den `newNonce`-Endpoint:

```
HEAD /v1/pki_int/roles/amar-demo/acme/new-nonce HTTP/1.1
Host: vault-2.0.0:8200
```

Vault antwortet mit einem frischen Nonce im Header:

```
HTTP/1.1 200 OK
Replay-Nonce: dmF1bHQwlvrchXsw-TYmqQU2CSsFARiJB5VpWzBjVN-w33HGrSjzQy9ShGclXg
Cache-Control: no-store
```

Der Nonce-Wert ist Base64url-kodiert und intern zeitlich limitiert.
Vault speichert ihn in der PKI-Engine-Storage. Nach einmaliger Verwendung
wird er invalidiert.

#### Schritt 2 — Nonce in JWS einbetten

Jeder ACME-Request wird als JWS (JSON Web Signature) versendet. Die Struktur:

```json
{
  "protected": "<base64url({
    'alg': 'RS256',
    'jwk': { ...public key... },
    'nonce': 'dmF1bHQwlvrchXsw-TYmqQU2CSsFARiJB5VpWzBjVN-w33HGrSjzQy9ShGclXg',
    'url': 'http://vault-2.0.0:8200/v1/pki_int/roles/amar-demo/acme/new-account'
  })>",
  "payload": "<base64url({ ...request body... })>",
  "signature": "<RSA-Signatur über protected.payload>"
}
```

Der `nonce`-Wert im `protected`-Header bindet den Request an genau diesen Moment.

#### Schritt 3 — Vault validiert den Nonce

Vault prüft beim Empfang:
1. Ist der Nonce-Wert bekannt (in Storage vorhanden)?
2. Wurde er noch nicht verwendet?
3. Ist die JWS-Signatur gültig?

Wenn der Nonce fehlt oder schon verwendet wurde, antwortet Vault mit:
```json
{ "type": "urn:ietf:params:acme:error:badNonce" }
```
Der Client muss dann einen neuen Nonce abrufen und es erneut versuchen.

#### Schritt 4 — Nonce aus POST-Response recyceln

Nach jedem erfolgreichen POST liefert Vault automatisch einen neuen Nonce
im Response-Header zurück. Der Client muss nicht zwingend immer den
`newNonce`-Endpoint aufrufen — er kann den Nonce aus der letzten Antwort
wiederverwenden.

### Vault-spezifische Besonderheit: `allowed_response_headers`

Vault filtert aus Sicherheitsgründen HTTP-Response-Header. Non-standard Headers
(wie `Replay-Nonce`) werden standardmäßig **nicht** durchgeleitet, auch wenn
der interne Handler sie setzt.

Für ACME muss der PKI-Mount explizit konfiguriert werden:

```bash
vault secrets tune pki_int \
  -passthrough-request-headers=If-Modified-Since \
  -allowed-response-headers=Last-Modified \
  -allowed-response-headers=Location \
  -allowed-response-headers=Replay-Nonce \
  -allowed-response-headers=Link
```

> **Das war die Root Cause** unseres Troubleshootings: Ohne dieses Tuning
> antwortete Vault korrekt (HTTP 200/204), aber der `Replay-Nonce` Header
> wurde still gefiltert — kein Fehler, kein Log, einfach kein Header.

### Die http-01 Challenge

ACME muss beweisen, dass der Antragsteller die Domain wirklich kontrolliert.
Die `http-01` Challenge funktioniert so:

1. Vault generiert einen zufälligen **Token** (z. B. `3MuuQcvMXn8cV-2-QGUdh34dOoMU`)
2. Der Client berechnet die **Key Authorization**: `token.SHA256(accountKey)`
3. Der Client stellt diese unter `http://<domain>/.well-known/acme-challenge/<token>` bereit
4. Vault macht einen HTTP-Request auf genau diese URL und prüft den Wert
5. Bei Erfolg: Vault stellt das Zertifikat aus

In dieser Demo wird ein temporärer HTTP-Server auf Port 80 gestartet,
der genau diesen Pfad beantwortet. Vault erreicht den Container über den
Docker-Netzwerk-DNS-Alias `amar-demo.local`.

### Python-Implementierung: Vault Nonce-Workaround

Die Standard-ACME-Library (`acme` 5.4.0) nutzt `HEAD` für den `newNonce`-Endpoint.
Vault Enterprise gibt den `Replay-Nonce` Header nur bei `GET` zurück — nicht bei `HEAD`.

Deshalb überschreiben wir die `_get_nonce` Methode in `app/acme_client.py`:

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

## 3. Vault PKI Aufbau

Die Vault-Konfiguration wird vollständig über Terraform verwaltet (`terraform/`).

### Zertifikatskette

```
Root CA (pki mount)
  Common Name: amar-demo.local Root CA
  TTL:         87600h (10 Jahre)
  Key:         RSA 4096

  └── Intermediate CA (pki_int mount)
        Common Name: amar-demo.local Intermediate CA
        TTL:         43800h (5 Jahre)
        Key:         RSA 4096

        └── Endnutzer-Zertifikate (Role: amar-demo)
              Domain:  amar-demo.local
              TTL:     3m  (Demo: sichtbare Erneuerung live beobachtbar)
              Key:     RSA 2048
```

### Kritische Terraform-Ressourcen

| Ressource | Zweck |
|---|---|
| `vault_mount.pki_root` | Root CA Mount mit `allowed_response_headers` |
| `vault_mount.pki_int` | Intermediate CA Mount mit ACME-Headers |
| `vault_pki_secret_backend_root_cert.root` | Root CA Zertifikat generieren |
| `vault_pki_secret_backend_intermediate_cert_request.int_csr` | CSR für Intermediate CA |
| `vault_pki_secret_backend_root_sign_intermediate.sign_int` | Root signiert Intermediate |
| `vault_pki_secret_backend_intermediate_set_signed.set_int` | Signiertes Cert in Mount laden |
| `vault_generic_endpoint.cluster_config` | `pki_int/config/cluster` — **Pflicht für ACME** |
| `vault_generic_endpoint.acme_config` | ACME aktivieren + Role erlauben |

### Warum ist `cluster_config` Pflicht?

Vault ACME braucht einen konfigurierten `cluster/path`, um:
- Die eigene ACME-Directory-URL zu konstruieren
- Interne ACME-Response-URLs zu generieren
- Den `api_addr` in ACME-Responses einzubetten

Ohne diesen Eintrag antwortet Vault mit `400 Bad Request: issuer does not exist`.

---

## 4. Demo starten (manuell)

### Voraussetzungen

- Docker Desktop mit aktivem `dev-network`
- Terraform installiert
- `/etc/hosts` Eintrag für die Demo-Domain

### Schritt 1 — Docker Netzwerk prüfen

```bash
docker network ls | grep dev-network
# Falls nicht vorhanden:
docker network create dev-network
```

### Schritt 2 — /etc/hosts Eintrag

```bash
echo "127.0.0.1 amar-demo.local" | sudo tee -a /etc/hosts
```

### Schritt 3 — Vault starten

```bash
cd ai-demo

docker run -d \
  --name vault-2.0.0 \
  --network dev-network \
  -p 8200:8200 \
  -p 8201:8201 \
  -e VAULT_LICENSE=<license-aus-vault-secrets.txt> \
  -v $(pwd)/vault-config/vault.hcl:/vault/config/vault.hcl \
  -v $(pwd)/vault-data:/vault/data \
  --cap-add=IPC_LOCK \
  hashicorp/vault-enterprise:2.0-ent \
  server
```

### Schritt 4 — Vault initialisieren oder entsiegeln

**Beim ersten Start (noch keine vault-data):**

```bash
# Initialisieren
curl -s -X POST http://0.0.0.0:8200/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{"secret_shares": 1, "secret_threshold": 1}'
# → Root Token und Unseal Key notieren (in vault-secrets.txt speichern)

# Entsiegeln
curl -s -X POST http://0.0.0.0:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "<UNSEAL_KEY>"}'
```

**Bei Neustart (vault-data existiert bereits):**

```bash
# Nur entsiegeln — Daten bleiben erhalten
curl -s -X POST http://0.0.0.0:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "<UNSEAL_KEY_AUS_VAULT_SECRETS_TXT>"}'
```

> **Wichtig:** Im Production-Mode (nicht dev) muss Vault nach jedem Neustart
> manuell entsiegelt werden. Die Daten in `vault-data/` bleiben erhalten.

### Schritt 5 — Vault PKI mit Terraform konfigurieren

```bash
cd terraform

# Beim ersten Start (kein tfstate):
terraform init
terraform apply -var="vault_token=<ROOT_TOKEN>"

# Bei Neustart (tfstate existiert, Vault wurde neu gestartet):
rm terraform.tfstate terraform.tfstate.backup
terraform apply -var="vault_token=<ROOT_TOKEN>"
```

### Schritt 6 — Demo Microservice starten

```bash
cd ..  # zurück in ai-demo/
docker compose up --build
```

Der Service:
1. Startet HTTP-Server auf Port 80 (ACME Challenge)
2. Registriert ACME-Account bei Vault
3. Führt http-01 Challenge durch
4. Empfängt signiertes TLS-Zertifikat
5. Startet HTTPS-Server auf Port 8443

### Schritt 7 — Root CA dem Mac vertrauen (einmalig)

```bash
curl -o /tmp/vault-root-ca.pem http://0.0.0.0:8200/v1/pki/ca/pem
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/vault-root-ca.pem
```

Browser neu starten. `https://amar-demo.local:8443` sollte jetzt grün sein.

### Demo stoppen

```bash
# Nur den Demo-Container stoppen (Vault bleibt laufen)
docker compose down

# Alles stoppen inkl. Vault
docker compose down
docker stop vault-2.0.0

# Vault-Daten vollständig löschen (nächster Start = Neuinitialisierung)
docker stop vault-2.0.0 && docker rm vault-2.0.0
rm -rf vault-data/*
```

> **Hinweis:** Vault-Daten in `vault-data/` bleiben beim normalen `docker stop`
> erhalten. Beim nächsten Start muss Vault nur entsiegelt werden (Schritt 4).
> Erst wenn `vault-data/` gelöscht wird, ist eine komplette Neuinitialisierung
> inkl. `terraform apply` notwendig.

---

## 5. Demo starten mit einem AI Assistenten

Du kannst Claude Code (oder einen anderen AI-Assistenten mit Zugriff auf
dieses Repository und Terminal) die gesamte Demo starten lassen.

### Prompt für den AI Assistenten

```
Ich möchte die Vault PKI ACME Demo starten. Das Projekt liegt unter
/Users/<dein-user>/coding/ai/ai-demo.

Bitte führe folgende Schritte durch:

1. Prüfe ob das Docker Netzwerk "dev-network" existiert, sonst erstelle es.

2. Prüfe ob der Vault Container "vault-2.0.0" bereits läuft.
   - Falls nicht: Starte ihn mit dem Befehl aus der README (Schritt 3).
     Den VAULT_LICENSE Wert findest du in vault-secrets.txt.

3. Prüfe ob Vault bereits initialisiert und entsiegelt ist:
   curl http://0.0.0.0:8200/v1/sys/health
   - initialized: false → initialisieren (Schritt 4, erster Start)
   - sealed: true → nur entsiegeln (Unseal Key aus vault-secrets.txt)
   - initialized: true, sealed: false → weiter mit Schritt 4

4. Prüfe ob der Terraform State existiert (terraform/terraform.tfstate).
   - Existiert nicht oder Vault wurde neu gestartet → terraform apply
     mit dem Root Token aus vault-secrets.txt

5. Starte den Demo Container:
   docker compose up --build -d

6. Zeige mir die Logs bis das Zertifikat ausgestellt wurde:
   docker logs vault-acme-demo -f

7. Teste den Endpoint:
   curl -sk --resolve "amar-demo.local:8443:127.0.0.1" https://amar-demo.local:8443/
```

### Was der AI Assistent dabei beachten muss

- **tfstate und Vault-Restart:** Der Terraform State referenziert Vault-interne
  IDs (Issuer-UUIDs). Nach einem Vault-Neustart sind diese IDs weg.
  Deshalb muss bei Neustart immer `terraform.tfstate` gelöscht und
  `terraform apply` neu ausgeführt werden.

- **Mount Tuning:** Das Mount-Tuning für `allowed_response_headers` ist
  bereits im Terraform-Code (`main.tf`) enthalten und wird automatisch
  beim `terraform apply` gesetzt.

- **Port 80:** Der Demo-Container braucht Port 80 für die ACME Challenge.
  Falls ein anderer Prozess Port 80 belegt, schlägt die Challenge fehl.

---

## 6. Endpoints testen

```bash
# Health Check + Zertifikat-Info
curl -sk --resolve "amar-demo.local:8443:127.0.0.1" \
  https://amar-demo.local:8443/ | python3 -m json.tool

# Vollständige Zertifikat-Details
curl -sk --resolve "amar-demo.local:8443:127.0.0.1" \
  https://amar-demo.local:8443/cert | python3 -m json.tool

# Mit Root CA verifizieren
curl -s http://0.0.0.0:8200/v1/pki/ca/pem -o /tmp/ca.pem
curl --cacert /tmp/ca.pem https://amar-demo.local:8443/

# Vault UI
open http://localhost:8200/ui
# Token: siehe vault-secrets.txt

# ACME Directory direkt
curl -s http://0.0.0.0:8200/v1/pki_int/roles/amar-demo/acme/directory | python3 -m json.tool

# Neuen Nonce abrufen (sollte Replay-Nonce Header zeigen)
curl -sI http://0.0.0.0:8200/v1/pki_int/roles/amar-demo/acme/new-nonce
```

### Endpoints im Überblick

| Endpoint | Format | Beschreibung |
|---|---|---|
| `GET /` | HTML | Modernes Web UI mit Live-Countdown und Renewal-Log |
| `GET /cert` | JSON | Zertifikat-Details als maschinenlesbares JSON |

### Erwartete Antwort von `GET /cert`

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

## 7. Live-Demo: Automatische Zertifikats-Erneuerung

> **Hinweis — Demo-Setup:** Dieses Setup mit Python/FastAPI und Uvicorn dient
> ausschließlich zu **Demo- und Lernzwecken**, um den ACME-Protokollablauf
> anschaulich zu machen. In Produktion würde man einen Webserver wie **nginx**
> einsetzen, der nach einem Zertifikat-Renewal mit `nginx -s reload` einen
> Zero-Downtime Hot-Reload durchführt — ohne Prozess-Neustart, ohne
> unterbrochene Verbindungen. Uvicorn hingegen muss neu gestartet werden
> (~1–2s Downtime), was für eine Demo akzeptabel, für Produktion aber
> nicht empfehlenswert ist.

Die Demo ist so konfiguriert, dass der gesamte ACME-Renewal-Zyklus in unter
3 Minuten live vor Kunden beobachtet werden kann — im Browser und in den Container-Logs.

### Konfiguration

```
Zertifikat TTL:   3m   (terraform/variables.tf → cert_ttl)
Erneuerung bei:  < 60s Restlaufzeit
Prüfintervall:    30s
```

### Was passiert im Hintergrund

```
T+0:00   Zertifikat ausgestellt (178s Laufzeit)
T+0:30   [renewal] Check → 148s remaining (threshold: 60s)
T+1:00   [renewal] Check → 118s remaining (threshold: 60s)
T+1:30   [renewal] Check → 88s remaining (threshold: 60s)
T+2:00   [renewal] Check → 58s remaining ← Threshold erreicht!
T+2:00   [renewal] *** ACME Renewal gestartet ***
T+2:03   [renewal] ✓ Neues Zertifikat — neue Serial, 178s gültig
T+2:03   [server]  HTTPS Server neu gestartet mit neuem Zertifikat
T+2:33   [renewal] Check → 148s remaining (nächster Zyklus)
```

### Logs live beobachten (für Kunden-Demo)

```bash
docker logs vault-acme-demo -f
```

Relevante Log-Zeilen die während der Demo erscheinen:

```
[renewal] Certificate check — 58s remaining (threshold: 60s)
[renewal] *** Threshold reached (58s < 60s) — starting ACME renewal ***
[renewal] ✓ New certificate obtained — serial 0x781eea…, valid for 178s
[renewal] Signalling HTTPS server to reload with new certificate...
[server]  Restarting HTTPS server with renewed certificate...
[server]  Starting HTTPS server on https://amar-demo.local:8443
```

### Web UI — Live Countdown im Browser

Öffne `https://amar-demo.local:8443` im Browser für das moderne Dashboard:

- **Großer Countdown-Timer** — zeigt die Restlaufzeit in MM:SS
  - Grün: > 3× Schwellwert (normal)
  - Orange: zwischen 1× und 3× Schwellwert (läuft ab)
  - Rot + blinkt: unter dem Schwellwert (Erneuerung wird gleich ausgelöst)
  - Violett pulsierend: Zertifikat abgelaufen / Erneuerung läuft
- **Validity-Balken** — depleting progress bar zeigt visuell wie weit das Zertifikat verbraucht ist
- **Renewal Counter** — zählt wie viele Erneuerungen bereits stattgefunden haben
- **Renewal Activity Log** — Zeitstempel jeder Erneuerung mit neuer Serial Number
- **Auto-Refresh** — Seite lädt alle 5 Sekunden neu und zeigt sofort das neue Zertifikat

### Warum nicht nginx? — Demo vs. Produktion

| | Diese Demo (Python/Uvicorn) | Produktions-Setup (nginx) |
|---|---|---|
| **Zweck** | ACME-Flow anschaulich machen | TLS-Termination im Betrieb |
| **Nach Renewal** | Uvicorn stoppen + neu starten | `nginx -s reload` (HUP Signal) |
| **Downtime** | ~1–2 Sekunden | 0 Sekunden (Zero-Downtime) |
| **Bestehende Verbindungen** | werden unterbrochen | werden noch fertig bearbeitet |
| **Mechanismus** | Prozess-Neustart | Hot-Reload — nur Worker tauschen |
| **Logs sichtbar?** | Ja — jeder Schritt geloggt | Kaum — läuft still im Hintergrund |

nginx unterstützt "graceful reload": Der Master-Prozess bleibt, neue Worker
laden das neue Zertifikat, alte Worker beenden laufende Requests sauber.
Tools wie **Certbot** nutzen genau das:

```bash
certbot renew --deploy-hook "nginx -s reload"
```

Uvicorn hat diesen Mechanismus nicht — weshalb wir den ganzen Server kurz
neustarten. Für die Demo ist das gewollt: Man sieht im Log und im Browser
exakt, wann das neue Zertifikat aktiv wird.

### Zertifikat-TTL für Produktion anpassen

Für einen echten Einsatz (nicht Demo) in `terraform/variables.tf`:

```hcl
variable "cert_ttl" {
  default = "720h"   # 30 Tage — typisch für Produktions-PKI
}
```

Und in `docker-compose.yml`:

```yaml
- RENEW_SECONDS=86400   # 24h vor Ablauf erneuern
- CHECK_INTERVAL=3600   # stündlich prüfen
```

---

## 8. Troubleshooting

### `acme.errors.MissingNonce` — kein Replay-Nonce Header

```bash
# Prüfen ob der Header gesetzt wird
curl -sI http://0.0.0.0:8200/v1/pki_int/roles/amar-demo/acme/new-nonce | grep -i replay

# Falls nicht → Mount Tuning prüfen
curl -s -H "X-Vault-Token: <TOKEN>" \
  http://0.0.0.0:8200/v1/sys/mounts/pki_int/tune | python3 -m json.tool | grep -A5 "allowed_response"

# Fix: Mount Tuning erneut anwenden
curl -X POST http://0.0.0.0:8200/v1/sys/mounts/pki_int/tune \
  -H "X-Vault-Token: <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"passthrough_request_headers":["If-Modified-Since"],
       "allowed_response_headers":["Last-Modified","Location","Replay-Nonce","Link"]}'
```

> **Docs:** [Mount Tune API](https://developer.hashicorp.com/vault/api-docs/system/mounts) · [PKI ACME](https://developer.hashicorp.com/vault/docs/secrets/pki/acme)

### `issuer does not exist` — 400 auf ACME Endpoints

Terraform State ist veraltet (Vault neu gestartet, alte Issuer-UUIDs im State):

```bash
cd terraform
rm terraform.tfstate terraform.tfstate.backup
# PKI Mounts aus Vault löschen falls vorhanden:
curl -X DELETE -H "X-Vault-Token: <TOKEN>" http://0.0.0.0:8200/v1/sys/mounts/pki
curl -X DELETE -H "X-Vault-Token: <TOKEN>" http://0.0.0.0:8200/v1/sys/mounts/pki_int
terraform apply -var="vault_token=<TOKEN>"
```

### Vault sealed nach Neustart

```bash
curl -s http://0.0.0.0:8200/v1/sys/health | python3 -c "import sys,json; print(json.load(sys.stdin)['sealed'])"
# true → entsiegeln:
curl -X POST http://0.0.0.0:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "<UNSEAL_KEY_AUS_VAULT_SECRETS_TXT>"}'
```

### ACME Challenge schlägt fehl

```bash
# Kann Vault den Demo-Container auf Port 80 erreichen?
docker exec vault-2.0.0 wget -q -O- http://amar-demo.local/.well-known/acme-challenge/test

# Ist der Container im richtigen Netzwerk?
docker inspect vault-acme-demo --format '{{json .NetworkSettings.Networks}}' | python3 -m json.tool
# Muss "dev-network" enthalten sein mit alias "amar-demo.local"
```

---

## 9. Projektstruktur

```
ai-demo/
├── app/
│   ├── acme_client.py       # ACME-Flow (http-01 Challenge, Vault-Nonce-Workaround)
│   ├── main.py              # FastAPI HTTPS-Server + Renewal Loop
│   └── requirements.txt     # Python Dependencies
│
├── terraform/
│   ├── main.tf              # PKI Root CA, Intermediate CA, ACME Config
│   ├── variables.tf         # vault_addr, vault_token, domain, cert_ttl
│   ├── outputs.tf           # ACME Directory URL, CA URLs, Service URL
│   └── provider.tf          # Terraform-Version + Vault Provider (hashicorp/vault ~> 4.0)
│
├── vault-config/
│   └── vault.hcl            # Vault Production Config (Raft, TLS-disable, UI)
│
├── vault-data/              # Raft Storage Volume (persistent)
│
├── docker-compose.yml       # Demo Microservice (dev-network, amar-demo.local alias)
├── Dockerfile               # Python 3.11 slim, Port 80 + 8443
├── vault-secrets.txt        # Root Token, Unseal Key, Enterprise License
└── README.md                # Diese Dokumentation
```

### Umgebungsvariablen (docker-compose.yml)

| Variable | Default | Beschreibung |
|---|---|---|
| `VAULT_ADDR` | `http://vault-2.0.0:8200` | Vault Adresse (Docker DNS) |
| `PKI_MOUNT` | `pki_int` | PKI Secrets Engine Mount |
| `PKI_ROLE` | `amar-demo` | PKI Role für Zertifikats-Ausstellung |
| `DOMAIN` | `amar-demo.local` | Domain des Zertifikats |
| `HTTPS_PORT` | `8443` | HTTPS Port des Microservice |
| `RENEW_SECONDS` | `60` | Sekunden vor Ablauf für Auto-Renewal |
| `CHECK_INTERVAL` | `30` | Prüfintervall in Sekunden |
