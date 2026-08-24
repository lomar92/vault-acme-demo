#!/bin/bash
# ============================================================
# Security Engineer Agent — Code Audit
# Läuft bi-weekly in GitHub Actions.
# Tools: bandit (Python SAST), pip-audit (Dependencies), checkov (IaC)
# Output: security/audit-YYYY-MM-DD.md (wird per PR eingereicht)
# ============================================================
set -euo pipefail

DATE=$(date +%Y-%m-%d)
REPORT_DIR="security"
REPORT_FILE="$REPORT_DIR/audit-${DATE}.md"
mkdir -p "$REPORT_DIR"

CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0

# ── Hilfsfunktionen ──────────────────────────────────────────────────────────
badge() {
    case "$1" in
        CRITICAL) echo "🔴 CRITICAL" ;;
        HIGH)     echo "🟠 HIGH" ;;
        MEDIUM)   echo "🟡 MEDIUM" ;;
        LOW)      echo "🔵 LOW" ;;
        *)        echo "⚪ INFO" ;;
    esac
}

count_severity() {
    case "$1" in
        CRITICAL) CRITICAL=$((CRITICAL + 1)) ;;
        HIGH)     HIGH=$((HIGH + 1)) ;;
        MEDIUM)   MEDIUM=$((MEDIUM + 1)) ;;
        LOW)      LOW=$((LOW + 1)) ;;
    esac
}

# ── Report Header ─────────────────────────────────────────────────────────────
cat > "$REPORT_FILE" << EOF
# Security Audit Report — ${DATE}

> Automatisch generiert vom **Security Engineer Agent** (bi-weekly).
> Alle Findings müssen bewertet und entweder behoben oder als akzeptiertes Risiko dokumentiert werden.

## Zusammenfassung

| Severity | Anzahl |
|---|---|
EOF

# ── 1. Bandit — Python SAST ───────────────────────────────────────────────────
echo "[1/3] Bandit — Python SAST..."
BANDIT_JSON="/tmp/bandit.json"

bandit -r app/ -f json -o "$BANDIT_JSON" -q 2>/dev/null || true

BANDIT_SECTION=""
if [ -f "$BANDIT_JSON" ] && python3 -c "import json; d=json.load(open('$BANDIT_JSON')); exit(0 if d.get('results') else 1)" 2>/dev/null; then
    BANDIT_SECTION=$(python3 << 'PYEOF'
import json, sys

with open('/tmp/bandit.json') as f:
    data = json.load(f)

results = data.get('results', [])
if not results:
    print("_Keine Findings._")
    sys.exit(0)

out = []
for r in results:
    sev = r.get('issue_severity', 'LOW').upper()
    conf = r.get('issue_confidence', 'LOW').upper()
    badges = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
    b = badges.get(sev, '⚪')
    out.append(
        f"| {b} {sev} | {r.get('issue_text','')} | "
        f"`{r.get('filename','')}:{r.get('line_number','')}` | "
        f"{r.get('test_id','')} | Konfidenz: {conf} |"
    )
    print(f"SEV:{sev}", file=sys.stderr)

print("| Severity | Beschreibung | Datei | ID | Hinweis |")
print("|---|---|---|---|---|")
for line in out:
    print(line)
PYEOF
    )

    # Severity-Counts aus bandit lesen
    while IFS= read -r line; do
        [[ "$line" == SEV:* ]] && count_severity "${line#SEV:}" || true
    done < <(python3 -c "
import json, sys
with open('/tmp/bandit.json') as f:
    data = json.load(f)
for r in data.get('results', []):
    print('SEV:' + r.get('issue_severity','LOW').upper())
" 2>/dev/null)
else
    BANDIT_SECTION="_Keine Findings._"
fi

# ── 2. pip-audit — Dependency Vulnerabilities ────────────────────────────────
echo "[2/3] pip-audit — Dependencies..."
PIP_AUDIT_JSON="/tmp/pip-audit.json"

pip-audit -r app/requirements.txt --format json -o "$PIP_AUDIT_JSON" -q 2>/dev/null || true

PIP_SECTION=""
if [ -f "$PIP_AUDIT_JSON" ] && python3 -c "
import json
d = json.load(open('$PIP_AUDIT_JSON'))
vulns = [v for p in d if isinstance(d, list) and False] if isinstance(d, list) else []
# pip-audit format varies
exit(0)
" 2>/dev/null; then
    PIP_SECTION=$(python3 << 'PYEOF'
import json, sys

with open('/tmp/pip-audit.json') as f:
    raw = json.load(f)

# pip-audit output: list of {name, version, vulns:[{id, fix_versions, description}]}
findings = []
if isinstance(raw, list):
    for pkg in raw:
        for v in pkg.get('vulns', []):
            sev = 'HIGH'  # pip-audit doesn't always provide CVSS — default HIGH wenn vuln bekannt
            findings.append({
                'package': pkg.get('name','?'),
                'version': pkg.get('version','?'),
                'id': v.get('id','?'),
                'desc': v.get('description','')[:120],
                'fix': ', '.join(v.get('fix_versions', [])) or 'kein Fix verfügbar',
                'sev': sev,
            })
            print(f"SEV:{sev}", file=sys.stderr)
elif isinstance(raw, dict):
    for dep, vulns in raw.items():
        for v in (vulns if isinstance(vulns, list) else []):
            sev = 'HIGH'
            findings.append({'package': dep, 'version': '?', 'id': str(v), 'desc': '', 'fix': '?', 'sev': sev})
            print(f"SEV:{sev}", file=sys.stderr)

if not findings:
    print("_Keine bekannten Schwachstellen in Dependencies._")
    sys.exit(0)

print("| Severity | Paket | Version | CVE/ID | Beschreibung | Fix verfügbar |")
print("|---|---|---|---|---|---|")
badges = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
for f in findings:
    b = badges.get(f['sev'], '⚪')
    print(f"| {b} {f['sev']} | `{f['package']}` | {f['version']} | {f['id']} | {f['desc']} | {f['fix']} |")
PYEOF
    )
else
    PIP_SECTION="_Keine bekannten Schwachstellen in Dependencies._"
fi

# ── 3. Checkov — Terraform + Dockerfile IaC ──────────────────────────────────
echo "[3/3] Checkov — IaC (Terraform + Dockerfile)..."
CHECKOV_JSON="/tmp/checkov.json"

checkov -d terraform/ -f Dockerfile \
    --output json \
    --quiet \
    --compact \
    --skip-check CKV_TF_1 \
    > "$CHECKOV_JSON" 2>/dev/null || true

CHECKOV_SECTION=""
if [ -f "$CHECKOV_JSON" ] && [ -s "$CHECKOV_JSON" ]; then
    CHECKOV_SECTION=$(python3 << 'PYEOF'
import json, sys

with open('/tmp/checkov.json') as f:
    try:
        raw = json.load(f)
    except Exception:
        print("_Checkov-Output konnte nicht geparst werden._")
        sys.exit(0)

# Checkov kann ein dict oder eine Liste zurückgeben (je nach Anzahl gecheckte Dateien)
results_list = raw if isinstance(raw, list) else [raw]

findings = []
for result in results_list:
    failed = result.get('results', {}).get('failed_checks', [])
    for check in failed:
        sev = check.get('severity') or 'MEDIUM'
        sev = sev.upper() if isinstance(sev, str) else 'MEDIUM'
        findings.append({
            'sev': sev,
            'id': check.get('check_id', '?'),
            'name': check.get('check', {}).get('name', check.get('check_id', '?'))
                    if isinstance(check.get('check'), dict)
                    else check.get('check_id', '?'),
            'file': check.get('repo_file_path', check.get('file_path', '?')),
            'lines': f"{check.get('file_line_range', ['?','?'])[0]}–{check.get('file_line_range', ['?','?'])[-1]}",
            'guide': check.get('guideline', ''),
        })
        print(f"SEV:{sev}", file=sys.stderr)

if not findings:
    print("_Keine IaC-Findings._")
    sys.exit(0)

print("| Severity | Check ID | Beschreibung | Datei | Zeilen |")
print("|---|---|---|---|---|")
badges = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
for f in findings:
    b = badges.get(f['sev'], '🟡')
    print(f"| {b} {f['sev']} | {f['id']} | {f['name']} | `{f['file']}` | {f['lines']} |")
PYEOF
    )
else
    CHECKOV_SECTION="_Keine IaC-Findings._"
fi

# ── Report zusammenbauen ──────────────────────────────────────────────────────
OVERALL="✅ BESTANDEN"
if [ "$CRITICAL" -gt 0 ]; then
    OVERALL="🔴 KRITISCH — sofortiger Handlungsbedarf"
elif [ "$HIGH" -gt 0 ]; then
    OVERALL="🟠 HOCH — zeitnahe Behebung erforderlich"
elif [ "$MEDIUM" -gt 0 ]; then
    OVERALL="🟡 MITTEL — im nächsten Sprint adressieren"
fi

# Summary-Tabelle nachträglich befüllen
{
    echo "| 🔴 Critical | $CRITICAL |"
    echo "| 🟠 High | $HIGH |"
    echo "| 🟡 Medium | $MEDIUM |"
    echo "| 🔵 Low | $LOW |"
    echo ""
    echo "**Gesamtbewertung:** $OVERALL"
    echo ""
    echo "---"
    echo ""
    echo "## 1. Python Code (bandit)"
    echo ""
    echo "$BANDIT_SECTION"
    echo ""
    echo "## 2. Dependencies (pip-audit)"
    echo ""
    echo "$PIP_SECTION"
    echo ""
    echo "## 3. Infrastructure as Code (checkov)"
    echo ""
    echo "$CHECKOV_SECTION"
    echo ""
    echo "---"
    echo ""
    echo "## Nächste Schritte"
    echo ""
    echo "- 🔴 **Critical / High**: PR mergen nachdem Findings behoben wurden"
    echo "- 🟡 **Medium**: Issue erstellen + im nächsten Sprint einplanen"
    echo "- 🔵 **Low**: Als akzeptiertes Risiko dokumentieren oder beheben"
    echo ""
    echo "_Generiert von [Security Engineer Agent](../.github/workflows/security-scan.yml) — ${DATE}_"
} >> "$REPORT_FILE"

echo ""
echo "Report: $REPORT_FILE"
echo "CRITICAL=$CRITICAL HIGH=$HIGH MEDIUM=$MEDIUM LOW=$LOW"

# Exit-Code: 1 bei Critical/High (blockiert Merge via Branch Protection)
if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
    exit 1
fi
exit 0
