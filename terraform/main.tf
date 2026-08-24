# ============================================================
# ROOT PKI ENGINE
# ============================================================

resource "vault_mount" "pki_root" {
  path                      = "pki"
  type                      = "pki"
  description               = "Root CA for ${var.domain}"
  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 315360000 # 10 years
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend            = vault_mount.pki_root.path
  type               = "internal"
  common_name        = "${var.domain} Root CA"
  ttl                = "87600h"
  format             = "pem"
  private_key_format = "der"
  key_type           = "rsa"
  key_bits           = 4096
  organization       = "Amar Demo Org"
  ou                 = "Platform"
  country            = "DE"
}

resource "vault_pki_secret_backend_config_urls" "root_urls" {
  backend                 = vault_mount.pki_root.path
  issuing_certificates    = ["${var.vault_addr}/v1/${vault_mount.pki_root.path}/ca"]
  crl_distribution_points = ["${var.vault_addr}/v1/${vault_mount.pki_root.path}/crl"]
}

# ============================================================
# INTERMEDIATE PKI ENGINE
# ============================================================

resource "vault_mount" "pki_int" {
  path                      = "pki_int"
  type                      = "pki"
  description               = "Intermediate CA for ${var.domain}"
  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 157680000 # 5 years

  # Required for ACME protocol (RFC 8555) — Vault blocks these headers by default
  passthrough_request_headers = ["If-Modified-Since"]
  allowed_response_headers    = ["Last-Modified", "Location", "Replay-Nonce", "Link"]
}

resource "vault_pki_secret_backend_intermediate_cert_request" "int_csr" {
  backend     = vault_mount.pki_int.path
  type        = "internal"
  common_name = "${var.domain} Intermediate CA"
  key_type    = "rsa"
  key_bits    = 4096
  organization = "Amar Demo Org"
  ou          = "Platform"
  country     = "DE"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "sign_int" {
  backend     = vault_mount.pki_root.path
  csr         = vault_pki_secret_backend_intermediate_cert_request.int_csr.csr
  common_name = "${var.domain} Intermediate CA"
  ttl         = "43800h"
  format      = "pem_bundle"
  organization = "Amar Demo Org"
  ou          = "Platform"
  country     = "DE"
  revoke      = true
}

resource "vault_pki_secret_backend_intermediate_set_signed" "set_int" {
  backend     = vault_mount.pki_int.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.sign_int.certificate
}

resource "vault_pki_secret_backend_config_urls" "int_urls" {
  backend                 = vault_mount.pki_int.path
  issuing_certificates    = ["${var.vault_addr}/v1/${vault_mount.pki_int.path}/ca"]
  crl_distribution_points = ["${var.vault_addr}/v1/${vault_mount.pki_int.path}/crl"]

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.set_int]
}

# ============================================================
# PKI ROLE
# ============================================================

resource "vault_pki_secret_backend_role" "amar_demo" {
  backend            = vault_mount.pki_int.path
  name               = "amar-demo"
  allowed_domains    = [var.domain]
  allow_subdomains   = true
  allow_bare_domains = true
  max_ttl            = var.cert_ttl
  ttl                = var.cert_ttl
  key_type           = "rsa"
  key_bits           = 2048
  server_flag        = true
  client_flag        = false
  key_usage          = ["DigitalSignature", "KeyEncipherment"]
  ext_key_usage      = ["ServerAuth"]

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.set_int]
}

# ============================================================
# CLUSTER PATH (required for ACME — Vault needs to know its own URL)
# ============================================================

resource "vault_generic_endpoint" "cluster_config" {
  path                 = "${vault_mount.pki_int.path}/config/cluster"
  ignore_absent_fields = true

  data_json = jsonencode({
    path     = "http://${var.vault_docker_ip}:8200/v1/${vault_mount.pki_int.path}"
    aia_path = "http://${var.vault_docker_ip}:8200/v1/${vault_mount.pki_int.path}"
  })

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.set_int]
}

# ============================================================
# ACME CONFIGURATION (via generic endpoint)
# ============================================================

resource "vault_generic_endpoint" "acme_config" {
  path                 = "${vault_mount.pki_int.path}/config/acme"
  ignore_absent_fields = true

  data_json = jsonencode({
    enabled       = true
    allowed_roles = ["amar-demo"]
    eab_policy    = "not-required"
  })

  depends_on = [
    vault_pki_secret_backend_role.amar_demo,
    vault_generic_endpoint.cluster_config,
  ]
}

# ============================================================
# CRL CONFIGURATION
# ============================================================

resource "vault_generic_endpoint" "crl_config" {
  path                 = "${vault_mount.pki_int.path}/config/crl"
  ignore_absent_fields = true

  data_json = jsonencode({
    expiry   = "72h"
    disable  = false
  })

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.set_int]
}
