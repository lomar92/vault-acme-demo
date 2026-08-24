#!/bin/bash
# ============================================================
# Security Engineer Agent — Pre-Commit Secret Scanner
# Bricht ab wenn sensible Daten im Staging-Bereich gefunden werden.
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
FOUND=0

flag() {
    echo -e "${RED}[SECURITY]${NC} $1"
    FOUND=1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Dateien die sich im Staging-Bereich befinden
STAGED=$(git diff --cached --name-only 2>/dev/null || true)

if [ -z "$STAGED" ]; then
    exit 0
fi

echo -e "${GREEN}[security-check]${NC} Scanne $(echo "$STAGED" | wc -l | tr -d ' ') Dateien..."

# ── 1. Verbotene Dateien ────────────────────────────────────────────────────
BLOCKED_FILES=(
    "vault-secrets.txt"
    "terraform.tfstate"
    "terraform.tfstate.backup"
)

for BLOCKED in "${BLOCKED_FILES[@]}"; do
    if echo "$STAGED" | grep -q "$BLOCKED"; then
        flag "Verbotene Datei im Commit: $BLOCKED"
    fi
done

# ── 2. Vault Token Pattern (hvs. / hvb. / s.) ───────────────────────────────
if git diff --cached | grep -qE '(hvs\.|hvb\.)[A-Za-z0-9]{20,}'; then
    flag "Vault Token gefunden (hvs./hvb. Präfix)"
    git diff --cached | grep -nE '(hvs\.|hvb\.)[A-Za-z0-9]{20,}' | head -5
fi

# ── 3. Private Key Header ────────────────────────────────────────────────────
if git diff --cached | grep -qE '^\+-----(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)-----'; then
    flag "Private Key im Commit gefunden"
    git diff --cached | grep -nE '^\+-----BEGIN.*PRIVATE KEY' | head -5
fi

# ── 4. Vault Enterprise License Pattern ─────────────────────────────────────
# Vault Lizenzen sind base32-kodiert, typisch 700+ Zeichen, beginnen mit 02MV4
if git diff --cached | grep -qE '02MV4[A-Z0-9]{20,}'; then
    flag "Vault Enterprise License gefunden"
fi

# ── 5. Unseal Key Pattern (64-char Hex) ─────────────────────────────────────
if git diff --cached | grep -qE 'Unseal Key.*:[[:space:]]*[0-9a-f]{64}'; then
    flag "Vault Unseal Key gefunden"
fi

# ── 6. Generische Secret-Pattern ────────────────────────────────────────────
# Hartcodierte Tokens/Passwörter in Assignments
if git diff --cached | grep -qiE '(password|passwd|secret|api_key|auth_token)\s*=\s*["\x27][^"\x27$\{]{8,}'; then
    warn "Mögliches hardcodiertes Secret in Zuweisung — bitte prüfen"
    git diff --cached | grep -niE '(password|passwd|secret|api_key|auth_token)\s*=\s*["\x27][^"\x27$\{]{8,}' | head -5
fi

# ── 7. .pem / .key Dateien ───────────────────────────────────────────────────
if echo "$STAGED" | grep -qE '\.(pem|key|p12|pfx)$'; then
    flag "Zertifikat-/Key-Datei im Commit: $(echo "$STAGED" | grep -E '\.(pem|key|p12|pfx)$')"
fi

# ── 8. vault-data/ Pfade ────────────────────────────────────────────────────
if echo "$STAGED" | grep -q 'vault-data/'; then
    flag "vault-data/ Inhalt im Commit (enthält CA Private Keys)"
fi

# ── Ergebnis ─────────────────────────────────────────────────────────────────
echo ""
if [ "$FOUND" -eq 1 ]; then
    echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  COMMIT ABGEBROCHEN — Sensible Daten gefunden   ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Prüfe .gitignore und entferne sensible Dateien aus dem Staging:"
    echo "  git restore --staged <datei>"
    exit 1
else
    echo -e "${GREEN}[✓] Keine sensiblen Daten gefunden — Commit erlaubt${NC}"
    exit 0
fi
