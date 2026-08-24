"""
Vault PKI ACME Demo — Python Microservice
==========================================
Requests a TLS certificate from Vault via ACME (http-01),
then serves an HTTPS endpoint on port 8443 with a modern web UI.

Endpoints:
  GET /       — Modern web UI with live certificate countdown
  GET /cert   — Full certificate details (JSON)
"""

import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from cryptography import x509
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from acme_client import obtain_certificate

# ── Configuration ─────────────────────────────────────────────────────────────

VAULT_ADDR     = os.getenv("VAULT_ADDR",        "http://host.docker.internal:8200")
PKI_MOUNT      = os.getenv("PKI_MOUNT",         "pki_int")
PKI_ROLE       = os.getenv("PKI_ROLE",          "amar-demo")
DOMAIN         = os.getenv("DOMAIN",            "amar-demo.local")
HTTPS_PORT     = int(os.getenv("HTTPS_PORT",    "8443"))
RENEW_SECONDS  = int(os.getenv("RENEW_SECONDS", "60"))   # renew when < 60s left
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "30"))  # check every 30s

CERT_PATH = "/app/certs/cert.pem"
KEY_PATH  = "/app/certs/key.pem"

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("vault-acme-demo")

# ── Global state ──────────────────────────────────────────────────────────────

_cert_renewed  = threading.Event()
_server_lock   = threading.Lock()
_server_ref    = [None]         # mutable ref to running uvicorn.Server
_renewal_count = [0]
_activity_log  = []             # [(timestamp_str, message), ...]


def _log_activity(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    _activity_log.append((ts, msg))
    if len(_activity_log) > 15:
        _activity_log.pop(0)

# ── FastAPI ───────────────────────────────────────────────────────────────────

app = FastAPI(title="Vault PKI ACME Demo", version="2.0.0")


def _parse_cert(cert_path: str) -> dict:
    cert_pem = Path(cert_path).read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    now = datetime.now(timezone.utc)

    try:
        not_before = cert.not_valid_before_utc
        not_after  = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    expires_in = (not_after - now).total_seconds()
    total_ttl  = (not_after - not_before).total_seconds()

    return {
        "subject":            cert.subject.rfc4514_string(),
        "issuer":             cert.issuer.rfc4514_string(),
        "serial_number":      hex(cert.serial_number),
        "not_before":         not_before.isoformat(),
        "not_after":          not_after.isoformat(),
        "not_after_iso":      not_after.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "expires_in_seconds": int(expires_in),
        "expires_in_hours":   round(expires_in / 3600, 4),
        "expires_in_days":    round(expires_in / 86400, 4),
        "total_ttl_seconds":  int(max(total_ttl, 1)),
        "sans":               sans,
        "valid":              now < not_after,
    }


# ── HTML template ─────────────────────────────────────────────────────────────

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vault PKI — ACME Demo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:           #0d1117;
      --surface:      #161b22;
      --surface-2:    #21262d;
      --border:       #30363d;
      --text:         #e6edf3;
      --text-muted:   #8b949e;
      --accent:       #7c3aed;
      --accent-light: #a78bfa;
      --green:        #3fb950;
      --orange:       #d29922;
      --red:          #f85149;
      --font:         'Inter', system-ui, -apple-system, sans-serif;
      --mono:         'JetBrains Mono', 'Fira Code', monospace;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
    }

    /* ── Header ── */
    header {
      width: 100%;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 1rem 2rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .logo-badge {
      background: var(--accent);
      color: #fff;
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      padding: 0.25rem 0.65rem;
      border-radius: 4px;
    }
    header h1 { font-size: 1rem; font-weight: 600; }
    .header-right {
      margin-left: auto;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.8rem;
      color: var(--text-muted);
    }
    .status-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }

    /* ── Layout ── */
    main {
      width: 100%;
      max-width: 920px;
      padding: 2rem 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }

    /* ── Countdown hero ── */
    .countdown-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 2.5rem 2rem 2rem;
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .countdown-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--accent-light));
    }
    .countdown-label {
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 1rem;
    }
    .countdown-timer {
      font-family: var(--mono);
      font-size: clamp(3rem, 8vw, 5rem);
      font-weight: 800;
      letter-spacing: -0.02em;
      color: var(--green);
      line-height: 1;
      transition: color 0.4s ease;
    }
    .countdown-timer.warning  { color: var(--orange); }
    .countdown-timer.critical { color: var(--red); }
    .countdown-timer.renewing { color: var(--accent-light); animation: blink 0.7s infinite; }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.4} }

    .countdown-sub {
      margin-top: 0.6rem;
      font-size: 0.82rem;
      color: var(--text-muted);
    }
    .validity-bar-wrap {
      margin-top: 1.5rem;
      background: var(--surface-2);
      border-radius: 999px;
      height: 6px;
      overflow: hidden;
    }
    .validity-bar {
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, var(--accent), var(--green));
      transition: width 1s linear, background 0.4s ease;
    }

    /* ── Metrics ── */
    .metrics-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1rem;
    }
    .metric-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.2rem 1.5rem;
    }
    .metric-label {
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 0.4rem;
    }
    .metric-value {
      font-family: var(--mono);
      font-size: 1.6rem;
      font-weight: 700;
      color: var(--accent-light);
    }
    .metric-unit {
      font-size: 0.78rem;
      color: var(--text-muted);
      margin-left: 0.2rem;
    }

    /* ── Info grid ── */
    .info-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }
    .info-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.2rem 1.5rem;
    }
    .info-card h3 {
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 0.75rem;
      padding: 0.35rem 0;
      font-size: 0.82rem;
    }
    .info-row + .info-row { border-top: 1px solid var(--border); }
    .info-key { color: var(--text-muted); white-space: nowrap; flex-shrink: 0; }
    .info-val {
      font-family: var(--mono);
      color: var(--text);
      text-align: right;
      word-break: break-all;
      font-size: 0.76rem;
    }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.55rem;
      border-radius: 4px;
      font-size: 0.68rem;
      font-weight: 700;
      font-family: var(--font);
    }
    .badge-green  { background: rgba(63,185,80,.15);  color: var(--green);  }
    .badge-purple { background: rgba(124,58,237,.15); color: var(--accent-light); }

    /* ── Activity log ── */
    .log-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.2rem 1.5rem;
    }
    .log-card h3 {
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
    }
    .log-entries {
      font-family: var(--mono);
      font-size: 0.77rem;
      color: var(--text-muted);
      line-height: 1.9;
      max-height: 140px;
      overflow-y: auto;
    }
    .log-ts  { color: var(--accent-light); }
    .log-msg { color: var(--text); }

    footer {
      margin-top: auto;
      padding: 1.5rem;
      font-size: 0.75rem;
      color: var(--text-muted);
      text-align: center;
    }
    footer a { color: var(--accent-light); text-decoration: none; }

    @media (max-width: 620px) {
      .metrics-row { grid-template-columns: 1fr; }
      .info-grid   { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <span class="logo-badge">HashiCorp Vault</span>
    <h1>PKI &mdash; ACME Certificate Demo</h1>
    <div class="header-right">
      <span class="status-dot" id="statusDot"></span>
      <span id="statusText">Active</span>
    </div>
  </header>

  <main>
    <div class="countdown-card">
      <div class="countdown-label">Certificate Expires In</div>
      <div class="countdown-timer" id="countdown">--:--</div>
      <div class="countdown-sub">Valid until {{NOT_AFTER_DISPLAY}}</div>
      <div class="validity-bar-wrap">
        <div class="validity-bar" id="validityBar"></div>
      </div>
    </div>

    <div class="metrics-row">
      <div class="metric-card">
        <div class="metric-label">Renewals</div>
        <div class="metric-value">{{RENEWAL_COUNT}}<span class="metric-unit">total</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Renewal Threshold</div>
        <div class="metric-value">{{RENEW_SECONDS}}<span class="metric-unit">s</span></div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Check Interval</div>
        <div class="metric-value">{{CHECK_INTERVAL}}<span class="metric-unit">s</span></div>
      </div>
    </div>

    <div class="info-grid">
      <div class="info-card">
        <h3>Certificate</h3>
        <div class="info-row">
          <span class="info-key">Domain (SAN)</span>
          <span class="info-val">{{DOMAIN}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Serial</span>
          <span class="info-val" style="font-size:0.65rem">{{SERIAL}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Not Before</span>
          <span class="info-val">{{NOT_BEFORE}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Not After</span>
          <span class="info-val">{{NOT_AFTER}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Status</span>
          <span class="info-val"><span class="badge badge-green">Valid</span></span>
        </div>
      </div>

      <div class="info-card">
        <h3>Vault PKI</h3>
        <div class="info-row">
          <span class="info-key">Vault Addr</span>
          <span class="info-val">{{VAULT_ADDR}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">PKI Mount</span>
          <span class="info-val">{{PKI_MOUNT}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">PKI Role</span>
          <span class="info-val">{{PKI_ROLE}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Issuer CN</span>
          <span class="info-val" style="font-size:0.65rem">{{ISSUER}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Protocol</span>
          <span class="info-val"><span class="badge badge-purple">ACME (RFC 8555)</span></span>
        </div>
      </div>
    </div>

    <div class="log-card">
      <h3>Renewal Activity</h3>
      <div class="log-entries">{{LOG_ENTRIES}}</div>
    </div>
  </main>

  <footer>
    Powered by <a href="https://www.vaultproject.io" target="_blank">HashiCorp Vault Enterprise</a>
    &mdash; auto-refreshes every 5s
  </footer>

  <script>
    const expiresAt = new Date("{{NOT_AFTER_ISO}}");
    const totalTTL  = {{TOTAL_TTL_SECONDS}};
    const warnAt    = {{RENEW_SECONDS_JS}};

    function fmt(sec) {
      if (sec <= 0) return "00:00";
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = Math.floor(sec % 60);
      if (h > 0)
        return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
      return `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
    }

    function tick() {
      const left = Math.max(0, (expiresAt - Date.now()) / 1000);
      const el   = document.getElementById('countdown');
      const bar  = document.getElementById('validityBar');
      const dot  = document.getElementById('statusDot');
      const txt  = document.getElementById('statusText');

      el.textContent = fmt(left);
      const pct = Math.min(100, Math.max(0, (left / totalTTL) * 100));
      bar.style.width = pct + '%';

      if (left <= 0) {
        el.className = 'countdown-timer renewing';
        dot.style.background = 'var(--accent-light)';
        txt.textContent = 'Renewing\u2026';
        bar.style.background = 'var(--accent)';
      } else if (left <= warnAt) {
        el.className = 'countdown-timer critical';
        dot.style.background = 'var(--red)';
        txt.textContent = 'Renewing Soon';
        bar.style.background = 'linear-gradient(90deg,var(--red),var(--orange))';
      } else if (left <= warnAt * 3) {
        el.className = 'countdown-timer warning';
        dot.style.background = 'var(--orange)';
        txt.textContent = 'Active';
        bar.style.background = 'linear-gradient(90deg,var(--orange),var(--accent-light))';
      } else {
        el.className = 'countdown-timer';
        dot.style.background = 'var(--green)';
        txt.textContent = 'Active';
        bar.style.background = 'linear-gradient(90deg,var(--accent),var(--green))';
      }
    }

    tick();
    setInterval(tick, 1000);
    // Hard-reload every 5 seconds to pick up renewed cert data
    setInterval(() => location.reload(), 5000);
  </script>
</body>
</html>"""


def _render_html() -> str:
    cert = _parse_cert(CERT_PATH)

    # Build log entries HTML
    if _activity_log:
        log_html = "\n".join(
            f'<div><span class="log-ts">[{ts}]</span> <span class="log-msg">{msg}</span></div>'
            for ts, msg in reversed(_activity_log)
        )
    else:
        log_html = '<div style="color:var(--text-muted)">No renewal activity yet</div>'

    not_after_dt = datetime.fromisoformat(cert["not_after"])
    not_before_dt = datetime.fromisoformat(cert["not_before"])

    html = _HTML
    html = html.replace("{{NOT_AFTER_DISPLAY}}", not_after_dt.strftime("%Y-%m-%d %H:%M:%S UTC"))
    html = html.replace("{{NOT_AFTER_ISO}}",     cert["not_after_iso"])
    html = html.replace("{{NOT_AFTER}}",         not_after_dt.strftime("%Y-%m-%d %H:%M UTC"))
    html = html.replace("{{NOT_BEFORE}}",        not_before_dt.strftime("%Y-%m-%d %H:%M UTC"))
    html = html.replace("{{RENEWAL_COUNT}}",     str(_renewal_count[0]))
    html = html.replace("{{RENEW_SECONDS}}",     str(RENEW_SECONDS))
    html = html.replace("{{RENEW_SECONDS_JS}}",  str(RENEW_SECONDS))
    html = html.replace("{{CHECK_INTERVAL}}",    str(CHECK_INTERVAL))
    html = html.replace("{{DOMAIN}}",            DOMAIN)
    html = html.replace("{{SERIAL}}",            cert["serial_number"])
    html = html.replace("{{VAULT_ADDR}}",        VAULT_ADDR)
    html = html.replace("{{PKI_MOUNT}}",         PKI_MOUNT)
    html = html.replace("{{PKI_ROLE}}",          PKI_ROLE)
    html = html.replace("{{ISSUER}}",            cert["issuer"])
    html = html.replace("{{TOTAL_TTL_SECONDS}}", str(cert["total_ttl_seconds"]))
    html = html.replace("{{LOG_ENTRIES}}",       log_html)
    return html


@app.get("/", response_class=HTMLResponse, summary="Web UI with live countdown")
async def index():
    if not Path(CERT_PATH).exists():
        return HTMLResponse("<h1>No certificate yet</h1>", status_code=503)
    return HTMLResponse(_render_html())


@app.get("/cert", summary="Certificate details (JSON)")
async def cert_details():
    if not Path(CERT_PATH).exists():
        return JSONResponse(status_code=503, content={"error": "No certificate available yet"})
    return _parse_cert(CERT_PATH)


# ── Renewal background thread ─────────────────────────────────────────────────

def _renewal_loop():
    """Check every CHECK_INTERVAL seconds. Renew when < RENEW_SECONDS left."""
    logger.info(
        f"[renewal] Started — checking every {CHECK_INTERVAL}s, "
        f"renew threshold: {RENEW_SECONDS}s"
    )
    while True:
        time.sleep(CHECK_INTERVAL)
        if not Path(CERT_PATH).exists():
            continue
        try:
            cert = _parse_cert(CERT_PATH)
            left = cert["expires_in_seconds"]
            logger.info(
                f"[renewal] Certificate check — {left}s remaining "
                f"(threshold: {RENEW_SECONDS}s)"
            )
            if left < RENEW_SECONDS:
                logger.info(
                    f"[renewal] *** Threshold reached ({left}s < {RENEW_SECONDS}s) — "
                    f"starting ACME renewal ***"
                )
                _log_activity(f"Renewal triggered — {left}s remaining")
                obtain_certificate(VAULT_ADDR, PKI_MOUNT, PKI_ROLE, DOMAIN)
                _renewal_count[0] += 1
                new_cert = _parse_cert(CERT_PATH)
                logger.info(
                    f"[renewal] ✓ New certificate obtained — serial {new_cert['serial_number']}, "
                    f"valid for {new_cert['expires_in_seconds']}s"
                )
                _log_activity(
                    f"Renewal #{_renewal_count[0]} complete — "
                    f"serial {new_cert['serial_number'][:10]}… "
                    f"valid {new_cert['expires_in_seconds']}s"
                )
                logger.info("[renewal] Signalling HTTPS server to reload with new certificate...")
                _cert_renewed.set()
                with _server_lock:
                    if _server_ref[0] is not None:
                        _server_ref[0].should_exit = True
        except Exception as exc:
            logger.error(f"[renewal] Error: {exc}")


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 60)
    logger.info("  Vault PKI ACME Demo")
    logger.info("=" * 60)
    logger.info(f"  Vault:           {VAULT_ADDR}")
    logger.info(f"  Domain:          {DOMAIN}")
    logger.info(f"  Port:            {HTTPS_PORT} (HTTPS)")
    logger.info(f"  Renew threshold: {RENEW_SECONDS}s")
    logger.info(f"  Check interval:  {CHECK_INTERVAL}s")
    logger.info("=" * 60)

    # Obtain initial certificate via ACME
    logger.info("[startup] Requesting certificate from Vault via ACME...")
    cert_path, key_path = obtain_certificate(VAULT_ADDR, PKI_MOUNT, PKI_ROLE, DOMAIN)
    cert_info = _parse_cert(cert_path)
    logger.info(f"[startup] Certificate obtained!")
    logger.info(f"[startup]   Subject:   {cert_info['subject']}")
    logger.info(f"[startup]   Issuer:    {cert_info['issuer']}")
    logger.info(f"[startup]   Serial:    {cert_info['serial_number']}")
    logger.info(f"[startup]   Valid for: {cert_info['expires_in_seconds']}s "
                f"({cert_info['expires_in_hours']}h)")
    _log_activity(f"Initial cert issued — serial {cert_info['serial_number'][:10]}…")

    # Start renewal thread
    renewal_thread = threading.Thread(target=_renewal_loop, daemon=True, name="cert-renewal")
    renewal_thread.start()

    # Server loop — restart uvicorn whenever cert is renewed
    while True:
        _cert_renewed.clear()
        logger.info(f"[server] Starting HTTPS server on https://{DOMAIN}:{HTTPS_PORT}")
        config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=HTTPS_PORT,
            ssl_certfile=cert_path,
            ssl_keyfile=key_path,
            log_level="warning",  # quiet uvicorn — demo logs come from our logger
        )
        server = uvicorn.Server(config)
        with _server_lock:
            _server_ref[0] = server
        server.run()

        if _cert_renewed.is_set():
            logger.info("[server] Restarting HTTPS server with renewed certificate...")
        else:
            logger.info("[server] Server exited normally.")
            break


if __name__ == "__main__":
    main()
