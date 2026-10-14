terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.49.2"
    }
  }
}

provider "google" {
  project = var.project_id
}
