#!/bin/bash
# deploy.sh — Vault PKI ACME Demo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SECRETS_FILE="$SCRIPT_DIR/vault-secrets.txt"
VAULT_ADDR="http://0.0.0.0:8200"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warning() { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${YELLOW}══ $* ══${NC}"; }

ROOT_TOKEN=$(grep "Root Token:" "$SECRETS_FILE" | awk '{print $3}')
UNSEAL_KEY=$(grep "Unseal Key:" "$SECRETS_FILE" | awk '{print $3}')

# ── 1. Docker-Netzwerk ───────────────────────────────────────────────────────
step "1. Docker-Netzwerk"
if ! docker network ls --format '{{.Name}}' | grep -q '^dev-network$'; then
    docker network create dev-network
    info "dev-network erstellt"
else
    info "dev-network existiert bereits"
fi

# ── 2. Vault Container ───────────────────────────────────────────────────────
step "2. Vault Container"
VAULT_WAS_STARTED=false
if docker ps --format '{{.Names}}' | grep -q '^vault-2\.0\.0$'; then
    info "vault-2.0.0 läuft bereits"
elif docker ps -a --format '{{.Names}}' | grep -q '^vault-2\.0\.0$'; then
    docker start vault-2.0.0 > /dev/null
    sleep 3
    info "vault-2.0.0 gestartet"
    VAULT_WAS_STARTED=true
else
    docker run -d \
        --name vault-2.0.0 \
        --network dev-network \
        -p 8200:8200 \
        -p 8201:8201 \
        -v "$SCRIPT_DIR/vault-config/vault.hcl:/vault/config/vault.hcl" \
        -v "$SCRIPT_DIR/vault-data:/vault/data" \
        --cap-add=IPC_LOCK \
        hashicorp/vault-enterprise:2.0-ent server > /dev/null
    sleep 5
    info "vault-2.0.0 erstellt und gestartet"
    VAULT_WAS_STARTED=true
fi

# ── 3. Vault entsiegeln ──────────────────────────────────────────────────────
step "3. Vault entsiegeln"
SEALED=$(curl -s "$VAULT_ADDR/v1/sys/health" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed', True))")
if [ "$SEALED" = "True" ]; then
    curl -s -X POST "$VAULT_ADDR/v1/sys/unseal" \
        -H "Content-Type: application/json" \
        -d "{\"key\": \"$UNSEAL_KEY\"}" > /dev/null
    info "Vault entsiegelt"
else
    info "Vault war bereits entsiegelt"
fi

# ── 4. Terraform — PKI + ACME ────────────────────────────────────────────────
step "4. Terraform — PKI + ACME"
cd "$SCRIPT_DIR/terraform"

# Nach Vault-Neustart: veraltete Issuer-UUIDs ungültig → tfstate + Mounts neu
NEEDS_CLEAN=false
[ "$VAULT_WAS_STARTED" = "true" ] && NEEDS_CLEAN=true
[ ! -f terraform.tfstate ]        && NEEDS_CLEAN=true

if [ "$NEEDS_CLEAN" = "true" ]; then
    warning "Räume veralteten tfstate und PKI Mounts auf..."
    rm -f terraform.tfstate terraform.tfstate.backup
    for MOUNT in pki pki_int; do
        curl -s -X DELETE \
            -H "X-Vault-Token: $ROOT_TOKEN" \
            "$VAULT_ADDR/v1/sys/mounts/$MOUNT" > /dev/null || true
    done
    info "Bereinigt"
fi

# vault-2.0.0 Hostname wird von Vault 2.0 URL-Validator abgelehnt → IP verwenden
VAULT_DOCKER_IP=$(docker inspect vault-2.0.0 \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
info "Vault IP auf dev-network: $VAULT_DOCKER_IP"

terraform init -no-color -upgrade > /dev/null
terraform apply -auto-approve -no-color \
    -var="vault_token=$ROOT_TOKEN" \
    -var="vault_docker_ip=$VAULT_DOCKER_IP"

cd "$SCRIPT_DIR"

# ── 5. Demo Container ────────────────────────────────────────────────────────
step "5. Demo Container"
docker compose up --build -d
sleep 5

# ── 6. Root CA → macOS Keychain + LibreSSL CA-Bundle ────────────────────────
step "6. Root CA Trust prüfen"

# Fingerprint der aktuellen Root CA aus Vault
VAULT_CA_FP=$(curl -s "$VAULT_ADDR/v1/pki/ca/pem" \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null)

# Fingerprint der Root CA im Keychain (falls vorhanden)
KEYCHAIN_CA_FP=$(security find-certificate -c "amar-demo.local Root CA" -p \
    /Library/Keychains/System.keychain 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null || echo "")

# End-to-End-Test: curl ohne -k — funktioniert nur wenn Trust korrekt gesetzt ist
CURL_TRUSTED=false
curl -sf --max-time 5 "https://amar-demo.local:8443/cert" > /dev/null 2>&1 \
    && CURL_TRUSTED=true || true

if [ "$VAULT_CA_FP" = "$KEYCHAIN_CA_FP" ] && [ "$CURL_TRUSTED" = "true" ]; then
    info "Root CA bereits korrekt vertraut — kein Update nötig"
else
    if [ "$VAULT_CA_FP" != "$KEYCHAIN_CA_FP" ]; then
        warning "Root CA Fingerprint hat sich geändert (Vault-Neustart?) — aktualisiere..."
    else
        warning "curl vertraut dem Zertifikat noch nicht — trage Root CA ein..."
    fi

    curl -s "$VAULT_ADDR/v1/pki/ca/pem" -o /tmp/vault-root-ca.pem

    # Keychain: altes Cert entfernen + aktuelles vertrauenswürdig eintragen
    sudo security delete-certificate -c "amar-demo.local Root CA" \
        /Library/Keychains/System.keychain 2>/dev/null || true
    sudo security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain \
        /tmp/vault-root-ca.pem

    # LibreSSL CA-Bundle: curl ohne -k
    sudo bash -c "cat /tmp/vault-root-ca.pem >> /etc/ssl/cert.pem"

    rm -f /tmp/vault-root-ca.pem
    info "Root CA eingetragen — Browser + curl vertrauen dem Zertifikat"
fi

echo -e "\n${GREEN}════════════════════════════════════${NC}"
echo -e "${GREEN}  Demo läuft!${NC}"
echo -e "${GREEN}════════════════════════════════════${NC}"
echo -e "  Web UI:  https://amar-demo.local:8443"
echo -e "  Cert:    curl -s https://amar-demo.local:8443/cert | python3 -m json.tool"
echo -e "  Logs:    docker logs -f vault-acme-demo"
echo -e "  Vault:   http://localhost:8200/ui"