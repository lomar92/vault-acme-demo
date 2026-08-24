storage "raft" {
  path    = "/vault/data"
  node_id = "vault-demo-node-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://vault-2.0.0:8200"
cluster_addr = "https://vault-2.0.0:8201"

ui            = true
disable_mlock = true
raw_storage_endpoint = true
