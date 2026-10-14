variable "organization_id" {
  description = "Numeric Google Cloud organization ID where the CMEK policy is enforced."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.organization_id))
    error_message = "organization_id must be a numeric organization ID without the organizations/ prefix."
  }
}

variable "project_id" {
  description = "Google Cloud administration project for provider/API context."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid 6-30 character Google Cloud project ID."
  }
}
