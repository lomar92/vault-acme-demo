#!/usr/bin/env python3
"""
Claude Security Engineer Agent
Runs bandit, pip-audit, and checkov, then sends the raw findings to Claude
for intelligent contextual analysis. Claude writes the PR body with plain-language
explanations, real-world severity assessment, and copy-paste-ready fixes.
"""
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

import anthropic


def run_cmd(cmd: list) -> str:
    """Run a command and return stdout. Never raises — returns empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout
    except Exception:
        return ""


def parse_json(raw: str) -> object:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}


def main():
    # Authentication — two modes:
    # 1. Workload Identity Federation (GitHub Actions, no static key):
    #    The workflow fetches a GitHub OIDC token and writes it to the path in
    #    ANTHROPIC_IDENTITY_TOKEN_FILE. The SDK exchanges it automatically on the
    #    first API call. Required env vars (set as GitHub Actions variables):
    #      ANTHROPIC_IDENTITY_TOKEN_FILE, ANTHROPIC_FEDERATION_RULE_ID,
    #      ANTHROPIC_ORGANIZATION_ID, ANTHROPIC_SERVICE_ACCOUNT_ID, ANTHROPIC_WORKSPACE_ID
    # 2. ANTHROPIC_API_KEY — fallback for local development.
    api_key = os.environ.get("ANTHROPIC_API_KEY")  # None → SDK uses WIF credentials

    today = date.today().isoformat()
    report_dir = Path("security")
    report_dir.mkdir(exist_ok=True)
    report_file = report_dir / f"audit-{today}.md"

    # ── 1. Run security tools ─────────────────────────────────────────────────
    print("[1/3] bandit — Python SAST...")
    bandit_raw = run_cmd(["bandit", "-r", "app/", "-f", "json", "-q"])
    bandit = parse_json(bandit_raw)
    bandit_results = bandit.get("results", []) if isinstance(bandit, dict) else []

    print("[2/3] pip-audit — dependency CVEs...")
    pip_raw = run_cmd(["pip-audit", "-r", "app/requirements.txt", "--format", "json"])
    pip_data = parse_json(pip_raw)
    pip_vulns = [
        {"package": p["name"], "version": p["version"], "vulns": p["vulns"]}
        for p in (pip_data if isinstance(pip_data, list) else [])
        if p.get("vulns")
    ]

    print("[3/3] checkov — IaC (Terraform + Dockerfile)...")
    checkov_raw = run_cmd([
        "checkov", "-d", "terraform/", "-f", "Dockerfile",
        "--output", "json", "--quiet", "--compact", "--skip-check", "CKV_TF_1",
    ])
    checkov = parse_json(checkov_raw)

    # ── 2. Count severities from raw tool output ──────────────────────────────
    critical = sum(1 for r in bandit_results if r.get("issue_severity", "").upper() == "CRITICAL")
    high = sum(1 for r in bandit_results if r.get("issue_severity", "").upper() == "HIGH")
    high += sum(len(p["vulns"]) for p in pip_vulns)  # pip-audit findings default to HIGH
    medium = sum(1 for r in bandit_results if r.get("issue_severity", "").upper() == "MEDIUM")
    low = sum(1 for r in bandit_results if r.get("issue_severity", "").upper() == "LOW")

    print(f"\n[Claude] Analyzing findings — Critical={critical} High={high} Medium={medium} Low={low}")

    # ── 3. Build prompt for Claude ────────────────────────────────────────────
    bandit_summary = json.dumps(bandit_results[:30], indent=2) if bandit_results else "No findings."
    pip_summary = json.dumps(pip_vulns[:20], indent=2) if pip_vulns else "No vulnerable packages."
    checkov_summary = json.dumps(checkov, indent=2)[:4000] if checkov else "No findings."

    prompt = f"""You are a senior security engineer reviewing automated scan results for a Python microservice.

**Project context:**
- FastAPI microservice that automatically obtains TLS certificates from HashiCorp Vault via the ACME protocol (http-01 challenge)
- Runs in Docker on a developer's local machine — internal demo environment, not internet-facing
- Infrastructure defined in Terraform (Vault PKI: Root CA → Intermediate CA → role)
- Python 3.11, dependencies in app/requirements.txt

**Raw tool findings:**

### bandit (Python SAST) — {len(bandit_results)} findings
```json
{bandit_summary}
```

### pip-audit (Dependency CVEs) — {sum(len(p["vulns"]) for p in pip_vulns)} vulnerable packages
```json
{pip_summary}
```

### checkov (Terraform + Dockerfile IaC) — failed checks
```json
{checkov_summary}
```

**Your task:** Write a GitHub Pull Request body in Markdown that a developer can immediately act on.

Structure:
1. **Summary table** — Critical / High / Medium / Low counts + overall verdict
2. **Findings by tool** — for each real finding (skip irrelevant or false positives for this context):
   - Plain-language explanation: what is the risk?
   - Context assessment: is it actually exploitable in THIS internal-only demo project?
   - Concrete fix: copy-paste-ready commands or code snippet
3. **Prioritized action checklist** — ordered by severity

Be direct and actionable. Avoid repeating findings that are clearly false positives or have no impact in a local demo environment. Overall verdict must appear in the summary.

Return ONLY the Markdown PR body — no preamble, no wrapping code fences."""

    # ── 4. Call Claude API ────────────────────────────────────────────────────
    # If api_key is None, the SDK automatically uses OIDC federated credentials.
    client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )

    report_content = message.content[0].text
    report_file.write_text(report_content)

    print(f"\nReport: {report_file}")
    print(f"CRITICAL={critical} HIGH={high} MEDIUM={medium} LOW={low}")

    # ── 5. Write outputs for GitHub Actions ───────────────────────────────────
    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"report_file={report_file}\n")
            f.write(f"date={today}\n")
            f.write(f"critical={critical}\n")
            f.write(f"high={high}\n")

    # Exit 1 triggers PR creation in the workflow (CRITICAL or HIGH found)
    sys.exit(1 if critical > 0 or high > 0 else 0)


if __name__ == "__main__":
    main()
