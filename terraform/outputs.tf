output "acme_directory_url" {
  description = "ACME directory URL (used by the microservice)"
  value       = "http://0.0.0.0:8200/v1/pki_int/roles/amar-demo/acme/directory"
}

output "root_ca_url" {
  description = "Root CA certificate URL"
  value       = "http://0.0.0.0:8200/v1/pki/ca/pem"
}

output "intermediate_ca_url" {
  description = "Intermediate CA certificate URL"
  value       = "http://0.0.0.0:8200/v1/pki_int/ca/pem"
}

output "service_url" {
  description = "HTTPS endpoint of the microservice"
  value       = "https://amar-demo.local:8443"
}

output "pki_role" {
  description = "PKI role name"
  value       = "amar-demo"
}
