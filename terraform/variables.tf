variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "http://0.0.0.0:8200"
}

variable "vault_token" {
  description = "Vault root token"
  type        = string
  default     = "root"
  sensitive   = true
}

variable "domain" {
  description = "Domain for the demo certificate"
  type        = string
  default     = "amar-demo.local"
}

variable "cert_ttl" {
  description = "TTL for issued certificates"
  type        = string
  default     = "3m"
}

variable "vault_docker_ip" {
  description = "IP address of the Vault container on dev-network (hostname vault-2.0.0 is rejected by Vault 2.0.0 URL validator)"
  type        = string
  default     = "172.19.0.2"
}
