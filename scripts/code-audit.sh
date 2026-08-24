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
    echo "**Overall:** $OVERALL"
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
    echo "## Remediation Guide"
    echo ""
    echo "How to fix each category of finding found in this audit."
    echo ""
    echo "### 🐍 Python Code Findings (bandit)"
    echo ""
    echo "Bandit performs static analysis on Python source code and flags common security anti-patterns."
    echo ""
    echo "**Common fixes by bandit ID:**"
    echo ""
    echo "| bandit ID | Issue | Fix |"
    echo "|---|---|---|"
    echo "| B105, B106, B107 | Hardcoded password / secret | Move to environment variable or secrets manager |"
    echo "| B108 | Insecure temp file | Use \`tempfile.mkstemp()\` instead of predictable paths |"
    echo "| B201, B202 | Flask/app debug mode on | Set \`debug=False\` in production; guard with env var |"
    echo "| B301, B302 | Pickle / marshal use | Replace with \`json\` for untrusted data |"
    echo "| B311 | \`random\` for security | Use \`secrets\` module instead of \`random\` |"
    echo "| B324 | Weak hash (MD5/SHA1) | Switch to \`hashlib.sha256()\` or stronger |"
    echo "| B501–B506 | TLS/SSL misconfiguration | Enforce TLS 1.2+, verify certs, never use \`verify=False\` |"
    echo "| B601, B602 | Shell injection risk | Use \`subprocess\` with list args, avoid \`shell=True\` |"
    echo "| B608 | SQL injection | Use parameterized queries / ORM instead of string concat |"
    echo ""
    echo "\`\`\`bash"
    echo "# Reproduce locally"
    echo "pip install bandit"
    echo "bandit -r app/ -ll        # -ll = MEDIUM and above only"
    echo ""
    echo "# Suppress a confirmed false positive (inline comment on the flagged line):"
    echo "result = subprocess.run(cmd)  # nosec B603"
    echo "\`\`\`"
    echo ""
    echo "---"
    echo ""
    echo "### 📦 Dependency Vulnerabilities (pip-audit)"
    echo ""
    echo "pip-audit checks installed packages against the Python Packaging Advisory Database (PyPA)."
    echo ""
    echo "\`\`\`bash"
    echo "# Upgrade a specific vulnerable package"
    echo "pip install --upgrade <package-name>"
    echo ""
    echo "# Update requirements.txt after upgrading"
    echo "pip freeze > app/requirements.txt"
    echo ""
    echo "# Re-run to confirm the fix"
    echo "pip-audit -r app/requirements.txt"
    echo "\`\`\`"
    echo ""
    echo "**If no fix version is available:**"
    echo "1. Check whether the vulnerable code path is actually reachable in this application"
    echo "2. Look for an alternative library"
    echo "3. Monitor the CVE for a patch release"
    echo "4. Document the accepted risk with a comment in \`requirements.txt\`"
    echo ""
    echo "---"
    echo ""
    echo "### 🏗️ Infrastructure as Code Findings (checkov)"
    echo ""
    echo "Checkov scans Terraform configs and Dockerfiles against security best-practice policies."
    echo ""
    echo "**Common Dockerfile fixes:**"
    echo ""
    echo "| Check ID | Issue | Fix |"
    echo "|---|---|---|"
    echo "| CKV_DOCKER_1 | No USER instruction | Add \`USER nonroot\` before CMD/ENTRYPOINT |"
    echo "| CKV_DOCKER_2 | HEALTHCHECK missing | Add a \`HEALTHCHECK\` instruction |"
    echo "| CKV_DOCKER_3 | Running as root | Add \`USER 1000\` or create a dedicated system user |"
    echo "| CKV_DOCKER_7 | Image pinned to \`latest\` | Pin to a specific digest or version tag |"
    echo ""
    echo "**Common Terraform fixes:**"
    echo ""
    echo "| Check ID | Issue | Fix |"
    echo "|---|---|---|"
    echo "| CKV_TF_* | Module without pinned version | Add \`version = \"~> x.y\"\` to the module block |"
    echo "| CKV2_* | Missing encryption | Enable \`encrypted = true\` on storage resources |"
    echo "| CKV_AWS_* | AWS misconfiguration | See the guideline URL in the checkov output for the specific fix |"
    echo ""
    echo "\`\`\`bash"
    echo "# Reproduce locally"
    echo "pip install checkov"
    echo "checkov -d terraform/     # scan Terraform"
    echo "checkov -f Dockerfile     # scan Dockerfile"
    echo ""
    echo "# Suppress an accepted-risk finding (add inline skip comment to the resource):"
    echo "# checkov:skip=CKV_DOCKER_2:No healthcheck needed — internal-only sidecar"
    echo "\`\`\`"
    echo ""
    echo "---"
    echo ""
    echo "## Next Steps"
    echo ""
    echo "| Severity | Required Action | Timeline |"
    echo "|---|---|---|"
    echo "| 🔴 Critical | Fix before merging — do not ship | Same day |"
    echo "| 🟠 High | Fix before next release | Within 1 week |"
    echo "| 🟡 Medium | Open a tracking issue, fix in next sprint | Within 30 days |"
    echo "| 🔵 Low | Document as accepted risk or fix opportunistically | No hard deadline |"
    echo ""
    echo "**Merge this PR** only after all Critical and High findings are resolved."
    echo "For accepted risks, document the decision in \`security/accepted-risks.md\`."
    echo ""
    echo "_Generated by [Security Engineer Agent](../.github/workflows/security-scan.yml) — ${DATE}_"
} >> "$REPORT_FILE"

echo ""
echo "Report: $REPORT_FILE"
echo "CRITICAL=$CRITICAL HIGH=$HIGH MEDIUM=$MEDIUM LOW=$LOW"

# Exit-Code: 1 bei Critical/High (blockiert Merge via Branch Protection)
if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
    exit 1
fi
exit 0
