#!/bin/bash
# ============================================================
# Security Engineer Agent — Full Repository Scanner
# Läuft in GitHub Actions (wöchentlich + bei Push/PR).
# Scannt alle getrackten Dateien + Git-Historie auf Secrets.
#
# GitHub Actions Annotations werden automatisch erkannt.
# Lokal: normale Terminal-Ausgabe.
# ============================================================
set -euo pipefail

# GitHub Actions Annotation Support
IN_CI="${GITHUB_ACTIONS:-false}"
FOUND=0

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

error() {
    local file="${2:-}"
    if [ "$IN_CI" = "true" ] && [ -n "$file" ]; then
        echo "::error file=$file::$1"
    fi
    echo -e "${RED}[SECURITY]${NC} $1"
    FOUND=1
}

warn() {
    local file="${2:-}"
    if [ "$IN_CI" = "true" ] && [ -n "$file" ]; then
        echo "::warning file=$file::$1"
    fi
    echo -e "${YELLOW}[WARN]${NC} $1"
}

info() { echo -e "${GREEN}[✓]${NC} $1"; }
section() { echo -e "\n${BOLD}── $1 ──${NC}"; }

echo -e "${BOLD}Security Engineer Agent — Repository Scan${NC}"
echo "Repository: $(git remote get-url origin 2>/dev/null || echo 'lokal')"
echo "Branch:     $(git branch --show-current 2>/dev/null || echo 'unbekannt')"
echo "Commit:     $(git rev-parse --short HEAD 2>/dev/null || echo 'unbekannt')"
echo ""

# ── 1. Verbotene Dateien im Repo ────────────────────────────────────────────
section "1. Verbotene Dateien"

MUST_NOT_BE_TRACKED=(
    "vault-secrets.txt"
    "terraform/terraform.tfstate"
    "terraform/terraform.tfstate.backup"
)

for F in "${MUST_NOT_BE_TRACKED[@]}"; do
    if git ls-files --error-unmatch "$F" > /dev/null 2>&1; then
        error "Sensible Datei ist im Repository getrackt: $F" "$F"
    fi
done

# .pem / .key Dateien die getrackt sind
TRACKED_CERTS=$(git ls-files | grep -E '\.(pem|key|p12|pfx)$' || true)
if [ -n "$TRACKED_CERTS" ]; then
    while IFS= read -r CERT_FILE; do
        error "Zertifikat-/Key-Datei getrackt: $CERT_FILE" "$CERT_FILE"
    done <<< "$TRACKED_CERTS"
fi

[ "$FOUND" -eq 0 ] && info "Keine verbotenen Dateien im Repository"

# ── 2. Secrets in getrackten Dateien ────────────────────────────────────────
section "2. Secret-Scan (aktuelle Dateien)"

while IFS= read -r FILE; do
    # Binärdateien überspringen
    if ! file "$FILE" | grep -qE 'text|ASCII|UTF'; then
        continue
    fi

    # Vault Token (hvs. / hvb.)
    if grep -qE '(hvs\.|hvb\.)[A-Za-z0-9]{20,}' "$FILE" 2>/dev/null; then
        error "Vault Token (hvs./hvb.) in: $FILE" "$FILE"
        grep -nE '(hvs\.|hvb\.)[A-Za-z0-9]{20,}' "$FILE" | head -3
    fi

    # Private Key Header (vollständiges PEM-Format mit Dashes — vermeidet False Positives in Code)
    if grep -qE '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' "$FILE" 2>/dev/null; then
        error "Private Key in: $FILE" "$FILE"
    fi

    # Vault Enterprise License (base32, beginnt mit 02MV4)
    if grep -qE '02MV4[A-Z0-9]{20,}' "$FILE" 2>/dev/null; then
        error "Vault Enterprise License in: $FILE" "$FILE"
        grep -nE '02MV4[A-Z0-9]{5}' "$FILE" | head -3
    fi

    # Unseal Key (64-char Hex nach "Unseal Key:")
    if grep -qE 'Unseal Key.*:[[:space:]]*[0-9a-f]{64}' "$FILE" 2>/dev/null; then
        error "Vault Unseal Key in: $FILE" "$FILE"
    fi

done < <(git ls-files)

[ "$FOUND" -eq 0 ] && info "Keine Secrets in getrackten Dateien gefunden"

# ── 3. Git-Historie scannen ──────────────────────────────────────────────────
section "3. Git-Historie (alle Commits)"

HISTORY_HITS=$(git log -p --all -- . 2>/dev/null \
    | grep -E '^\+(.*)(hvs\.|hvb\.)[A-Za-z0-9]{20,}|^(\+-----(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)-----|02MV4[A-Z0-9]{20,})' \
    | grep -v '^+++' | head -10 || true)

if [ -n "$HISTORY_HITS" ]; then
    error "Secrets in Git-Historie gefunden — selbst nach Löschen noch rekonstruierbar!"
    echo "$HISTORY_HITS" | head -5
    if [ "$IN_CI" = "true" ]; then
        echo "::error::Secrets in Git-Historie gefunden. Repo-History muss bereinigt werden (git filter-repo)."
    fi
fi

[ -z "$HISTORY_HITS" ] && info "Git-Historie sauber"

# ── 4. .gitignore Vollständigkeit prüfen ────────────────────────────────────
section "4. .gitignore Vollständigkeit"

MUST_BE_IGNORED=(
    "vault-secrets.txt"
    "vault-data/"
    "terraform/terraform.tfstate"
    "app/certs/"
)

for PATTERN in "${MUST_BE_IGNORED[@]}"; do
    if ! grep -q "$PATTERN" .gitignore 2>/dev/null; then
        warn ".gitignore fehlt Eintrag für: $PATTERN"
    fi
done

info ".gitignore geprüft"

# ── 5. Hardcodierte Credentials in Code ──────────────────────────────────────
section "5. Hardcodierte Credentials in Code"

CODE_FILES=$(git ls-files | grep -E '\.(py|sh|tf|yml|yaml|json|js|ts)$' || true)

if [ -n "$CODE_FILES" ]; then
    while IFS= read -r FILE; do
        if grep -qiE '(password|passwd|secret|api_key)\s*=\s*["'"'"'][^"'"'"'$\{]{8,}' "$FILE" 2>/dev/null; then
            warn "Mögliches hardcodiertes Secret in: $FILE" "$FILE"
            grep -niE '(password|passwd|secret|api_key)\s*=\s*["'"'"'][^"'"'"'$\{]{8,}' "$FILE" | head -3
        fi
    done <<< "$CODE_FILES"
fi

info "Code-Dateien auf hardcodierte Credentials geprüft"

# ── Ergebnis ──────────────────────────────────────────────────────────────────
echo ""
if [ "$FOUND" -eq 1 ]; then
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║  SECURITY SCAN FEHLGESCHLAGEN — Sofort handeln!     ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  Security Scan bestanden — Repository sauber         ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
    exit 0
fi
