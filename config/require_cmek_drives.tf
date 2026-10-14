# Enforcement policy requiring CMEK on all dynamically provisioned runtime drives
resource "google_compute_organization_security_policy_rule" "require_cmek_drives" {
  policy_id      = "dune-sub-storage-guard"
  action         = "deny"
  direction      = "INGRESS"
  priority       = 100
  match {
    config {
      src_ip_ranges = ["0.0.0.0/0"]
    }
    # Evaluates whether incoming compute request lacks Cloud KMS headers
    expression = "!has(resource.encryption_key) || resource.encryption_key.kms_key_name == ''"
  }
  description    = "Deny initialization of unencrypted drive infrastructure."
}
