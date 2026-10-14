# Require CMEK for supported new Compute Engine and Cloud Storage resources.
# This list constraint checks resource encryption; an ingress rule cannot do so.
resource "google_org_policy_policy" "require_cmek_drives" {
  name   = "organizations/${var.organization_id}/policies/gcp.restrictNonCmekServices"
  parent = "organizations/${var.organization_id}"

  spec {
    rules {
      values {
        denied_values = [
          "compute.googleapis.com",
          "storage.googleapis.com",
        ]
      }
    }
  }
}
