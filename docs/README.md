# Ecosystem document and source index

This collection contains 19 document text exports and 6 source/configuration snippets from the connected Google Drive framework materials.

Each archive preserves the available document text. The [source manifest](source_manifest.json) records original titles, source links, extracted sections, file sizes, SHA-256 hashes, and known limitations.

The [Dune-Sub integration verification](integration_verification.md) records passed integrity checks and the missing components that block runtime validation.

## Documents

| Archive | Original document |
| --- | --- |
| [acl source](archive/acl_source.txt) | [Google Drive](https://docs.google.com/document/d/1atQVZSdAapq16okzf2vAncbA8-cZ0ncSrCesxoIhsFs) |
| [active configuration](archive/active_configuration.txt) | [Google Drive](https://docs.google.com/document/d/1VDnNF6amuakldy8Vyy4BLPt-7VQU2BFDpSRRI6rv5bE/edit) |
| [blueprint license terms](archive/blueprint_license_terms.txt) | [Google Drive](https://docs.google.com/document/d/159O1ia_JfNwm-fEq_dazRd-ZFhwD0M35dPUoDxI5ubY/edit) |
| [build and deploy archive](archive/build_and_deploy_archive.txt) | [Google Drive](https://docs.google.com/document/d/1py3raULb01-SNt0sG-O5kchiDU1IxO8udVPJyf2DB4g/edit) |
| [crypto encryption](archive/crypto_encryption.txt) | [Google Drive](https://docs.google.com/document/d/1ZLbcMRqaz-pO_GhbXNlIYh7kBPyTF1Nnmzo7cbCMScw) |
| [crypto update](archive/crypto_update.txt) | [Google Drive](https://docs.google.com/document/d/1U_Mu-ZkPXtEfUBtpZiTkqnnmY_NJTCFsZTneP3Z8Ssc) |
| [deployment architecture blueprint](archive/deployment_architecture_blueprint.txt) | [Google Drive](https://docs.google.com/document/d/1-Dypm6YSEW9nLXisLBEd9nQ0TqZpuvm4XXnQ1jjRB_4/edit) |
| [deployment git commands](archive/deployment_git_commands.txt) | [Google Drive](https://docs.google.com/document/d/18sX26R5lyarUDv3DFZDumHqCze7YYlBOqNao8F_Gv3g/edit) |
| [deployment manifest](archive/deployment_manifest.txt) | [Google Drive](https://docs.google.com/document/d/12SKtGDXHOKYk4XZepaHM-vMWOq6SwFGuc3OYEqQGV-I/edit) |
| [device governance irs update](archive/device_governance_irs_update.txt) | [Google Drive](https://docs.google.com/document/d/171qWXqVnobMTdS1lM3ryzyfQqyXbGQQGJaHqOSCI3f4/edit) |
| [ecosystem update archive](archive/ecosystem_update_archive.txt) | [Google Drive](https://docs.google.com/document/d/1eKTW425QaMfWCXKR20uKa2NS7pbDW5O6lnw9mPCD1Yc/edit) |
| [evaluation api response archive](archive/evaluation_api_response_archive.txt) | [Google Drive](https://docs.google.com/document/d/1LJW5MeRwMUja14k2bFfETOyQsFLmf70JSeCzXWM0qTI/edit) |
| [framework handbook](archive/framework_handbook.txt) | [Google Drive](https://docs.google.com/document/d/1-JZHzK4FrWSoo40K5YYEOWqQyjZnEFAUqjjA5LA7WcM/edit) |
| [gacc business readiness](archive/gacc_business_readiness.txt) | [Google Drive](https://docs.google.com/document/d/1DpKM3U4hzpjULi5NPZB2eM7HMJPmT0GMPqDLnAQIOrg/edit) |
| [gacc repository packaging](archive/gacc_repository_packaging.txt) | [Google Drive](https://docs.google.com/document/d/18noyFtWacc7uHeIfx8MVAKc0besZQDIbZJkl3djTO-g/edit) |
| [github repository blueprint](archive/github_repository_blueprint.txt) | [Google Drive](https://docs.google.com/document/d/1vZfQehjVUJBtSPvzLzPzYkVF0Hfndb-s5OnNqzsP_ps/edit) |
| [mdm uem model](archive/mdm_uem_model.txt) | [Google Drive](https://docs.google.com/document/d/1-weF3Ic_iGhnueqJu8cNvFfb2AUfTU0S_M9pHUl4t5w/edit) |
| [protocolhub payload sync](archive/protocolhub_payload_sync.txt) | [Google Drive](https://docs.google.com/document/d/1YVWv2sq0WNd_HIKa-pVXHlsoMm3WhE21Kk3y91eKRbE/edit) |
| [subscriptions devices](archive/subscriptions_devices.txt) | [Google Drive](https://docs.google.com/document/d/1LpC3UJwfst2mHlOsteE_eif2780TX6TvPkXMzfMcK5s) |

## Extracted source and configuration

| File | Source section |
| --- | --- |
| [config/require_cmek_drives.tf](../config/require_cmek_drives.tf) | 2.1 Storage Array Re-Attestation & Policy Patching |
| [contracts/node_acl_smart_contract.sol](../contracts/node_acl_smart_contract.sol) | File_10: node_acl_smart_contract.sol |
| [examples/config/gacc.gitignore](../examples/config/gacc.gitignore) | 1. Immediate Next Step: Create a .gitignore |
| [examples/deployment/cloudbuild.yml](../examples/deployment/cloudbuild.yml) | 1. Finalized Deployment Manifest (cloudbuild.yaml) |
| [examples/exo-sync-validation.yml.example](../examples/exo-sync-validation.yml.example) | .github/workflows/exo-sync-validation.yml |
| [scripts/generate_blueprint.py](../scripts/generate_blueprint.py) | Python DOCX blueprint generator |

## Validation and limitations

The Python blueprint generator passes a syntax check. Solidity compilation and Terraform provider validation were unavailable in the upload workspace. Terraform and CI/CD snippets are reference examples; review their source-manifest notes before use. Workflow examples are stored outside the active GitHub Actions directory.

The discovered materials do not include the application files referenced in historical logs (`index.js`, `devicePolicy.json`, `gemWalletCollector.js`, or `nodeSyncer.js`), the referenced `GACC.7zip` package, or executable node-sync and hardware-attestation services.

Copyright, license, and confidentiality notices within the original documents and snippets are preserved. This collection does not resolve conflicting source notices or assert a new project-wide license.
