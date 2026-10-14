# Google Cloud CMEK organization policy

This Terraform configuration enforces `gcp.restrictNonCmekServices` for Compute
Engine (`compute.googleapis.com`) and Cloud Storage (`storage.googleapis.com`) at
the specified organization. Its deny list blocks creation of supported resources
without customer-managed encryption keys. Cloud Storage buckets must have a
default Cloud KMS key. Existing resources are not retroactively encrypted. See
[Google's CMEK organization policy documentation](https://docs.cloud.google.com/kms/docs/cmek-org-policy).

Use Terraform 1.5 or newer, below 2.0. The Google provider is pinned to 6.49.2.
`organization_id` is the numeric ID without the `organizations/` prefix;
`project_id` identifies the Google Cloud administration project used by the
provider. This directory is a standalone Terraform root module.

Before planning or applying, provide Application Default Credentials or an
impersonated service account with Organization Policy Administrator
(`roles/orgpolicy.policyAdmin`) on the target organization. Enable the Organization
Policy API (`orgpolicy.googleapis.com`) in the administration/quota project and
grant the identity permission to consume API quota there. Create suitable Cloud
KMS keys separately, enable the needed service APIs, and grant the Compute Engine
and Cloud Storage service agents Cloud KMS CryptoKey Encrypter/Decrypter
(`roles/cloudkms.cryptoKeyEncrypterDecrypter`) on the applicable keys. Use keys in
locations compatible with the disks and buckets. Configure the CMEK key on new
disks and the default CMEK key on new buckets before provisioning them.
This policy does not provision KMS keys, infrastructure, or IAM grants.

Run local validation without cloud credentials:

```sh
terraform -chdir=config init -backend=false
terraform -chdir=config validate
```

Plan with your actual organization and project IDs:

```sh
terraform -chdir=config plan \
  -var='organization_id=123456789' \
  -var='project_id=your-admin-project'
```

If a policy for this constraint already exists, import it into the Terraform
state before planning, then inspect the plan to preserve any existing service
restrictions:

```sh
terraform -chdir=config import \
  -var='organization_id=123456789' \
  -var='project_id=your-admin-project' \
  google_org_policy_policy.require_cmek_drives \
  organizations/123456789/policies/gcp.restrictNonCmekServices
```

The active repository workflow runs Terraform initialization and validation. It
does not apply the organization policy. Provider structure is documented in the
[Google provider resource reference](https://registry.terraform.io/providers/hashicorp/google/6.49.2/docs/resources/org_policy_policy).
