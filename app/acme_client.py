"""
ACME Client for Vault PKI
Handles certificate issuance and renewal via the ACME protocol.
"""

import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import josepy as jose
import requests
from acme import challenges, client, errors as acme_errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class _VaultClientNetwork(client.ClientNetwork):
    """Vault ACME only returns Replay-Nonce on GET requests, not HEAD.

    The standard acme library uses HEAD for nonce fetching (RFC 8555 §7.2).
    Vault Enterprise responds to HEAD without the Replay-Nonce header,
    so we override _get_nonce to use GET instead.
    """

    def _get_nonce(self, url: str, new_nonce_url: str) -> None:  # type: ignore[override]
        if not self._nonces:
            logger.debug("Requesting fresh nonce from Vault via GET")
            nonce_url = new_nonce_url if new_nonce_url is not None else url
            response = self._send_request("GET", nonce_url)
            self._add_nonce(response)
        return self._nonces.pop()

CERT_DIR = Path("/app/certs")

# Shared dict: token_path -> key_authorization string
# Used by the HTTP challenge server to serve responses
_challenge_responses: dict[str, str] = {}


# ============================================================
# HTTP Challenge Server (port 80)
# ============================================================

class _ChallengeHandler(BaseHTTPRequestHandler):
    """Minimal HTTP server to serve ACME http-01 challenge responses."""

    def do_GET(self):
        if self.path in _challenge_responses:
            body = _challenge_responses[self.path].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            logger.debug(f"Served challenge for path: {self.path}")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        logger.debug(f"[ChallengeHTTP] {fmt % args}")


def _run_challenge_server(server: HTTPServer):
    server.serve_forever()


# ============================================================
# Certificate helpers
# ============================================================

def _generate_account_key() -> jose.JWKRSA:
    return jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )


def _generate_domain_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_csr_pem(private_key: rsa.RSAPrivateKey, domain: str) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


# ============================================================
# Main ACME flow
# ============================================================

def obtain_certificate(
    vault_addr: str,
    pki_mount: str,
    pki_role: str,
    domain: str,
) -> tuple[str, str]:
    """
    Run the full ACME http-01 flow against Vault's PKI engine.

    Returns:
        (cert_path, key_path) — paths to the saved PEM files
    """
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    directory_url = f"{vault_addr}/v1/{pki_mount}/roles/{pki_role}/acme/directory"
    logger.info(f"ACME directory: {directory_url}")

    # ----------------------------------------------------------
    # 1. Start HTTP challenge server on port 80
    # ----------------------------------------------------------
    challenge_server = HTTPServer(("0.0.0.0", 80), _ChallengeHandler)
    challenge_thread = threading.Thread(
        target=_run_challenge_server,
        args=(challenge_server,),
        daemon=True,
    )
    challenge_thread.start()
    logger.info("Challenge HTTP server started on :80")

    try:
        # ----------------------------------------------------------
        # 2. Build ACME client
        # ----------------------------------------------------------
        account_key = _generate_account_key()

        # Use _VaultClientNetwork: Vault only returns Replay-Nonce on GET, not HEAD
        net = _VaultClientNetwork(account_key, verify_ssl=False)

        directory = messages.Directory.from_json(
            net.get(directory_url).json()
        )
        acme = client.ClientV2(directory, net)

        # ----------------------------------------------------------
        # 3. Register account
        # ----------------------------------------------------------
        logger.info("Registering ACME account...")
        acme.new_account(
            messages.NewRegistration.from_data(terms_of_service_agreed=True)
        )

        # ----------------------------------------------------------
        # 4. Generate domain key + CSR
        # ----------------------------------------------------------
        domain_key = _generate_domain_key()
        csr_pem = _build_csr_pem(domain_key, domain)

        # ----------------------------------------------------------
        # 5. Create order
        # ----------------------------------------------------------
        logger.info(f"Creating ACME order for {domain}...")
        order = acme.new_order(csr_pem)

        # ----------------------------------------------------------
        # 6. Find HTTP-01 challenge
        # ----------------------------------------------------------
        http01_challb = None
        for auth in order.authorizations:
            for challb in auth.body.challenges:
                if isinstance(challb.chall, challenges.HTTP01):
                    http01_challb = challb
                    break
            if http01_challb:
                break

        if not http01_challb:
            raise RuntimeError("Vault ACME did not offer an HTTP-01 challenge")

        # ----------------------------------------------------------
        # 7. Register challenge response in HTTP server
        # ----------------------------------------------------------
        challenge_path = http01_challb.chall.path  # /.well-known/acme-challenge/<token>
        response = http01_challb.chall.response(account_key)
        _challenge_responses[challenge_path] = response.key_authorization
        logger.info(f"Challenge response registered at {challenge_path}")

        # ----------------------------------------------------------
        # 8. Notify Vault the challenge is ready
        # ----------------------------------------------------------
        logger.info("Answering ACME challenge...")
        acme.answer_challenge(http01_challb, response)

        # ----------------------------------------------------------
        # 9. Poll until Vault validates + finalize order
        # ----------------------------------------------------------
        logger.info("Waiting for Vault to validate challenge and issue certificate...")
        finalized_order = acme.poll_and_finalize(order)

        # ----------------------------------------------------------
        # 10. Save certificate and key
        # ----------------------------------------------------------
        cert_path = CERT_DIR / "cert.pem"
        key_path = CERT_DIR / "key.pem"

        cert_path.write_text(finalized_order.fullchain_pem)
        key_path.write_bytes(
            domain_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        logger.info(f"Certificate saved: {cert_path}")
        logger.info(f"Private key saved: {key_path}")

        # Clean up challenge response
        _challenge_responses.pop(challenge_path, None)

        return str(cert_path), str(key_path)

    finally:
        challenge_server.shutdown()
        logger.info("Challenge HTTP server stopped")


def get_cert_expiry_hours(cert_path: str) -> float:
    """Return how many hours until the certificate expires."""
    from datetime import datetime, timezone

    cert_pem = Path(cert_path).read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    now = datetime.now(timezone.utc)

    # Support both old and new cryptography API
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        from datetime import timezone as tz
        not_after = cert.not_valid_after.replace(tzinfo=tz.utc)

    return (not_after - now).total_seconds() / 3600
