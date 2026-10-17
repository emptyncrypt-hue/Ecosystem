# Ecosystem

Device Policy Framework and Dune-Sub repository integration tools.

The repository includes the imported framework documents, maintained configuration examples, and a dependency-free Node.js toolchain for artifact validation, credential-pattern scanning, and guarded GitHub synchronization.

## Run the checks

Use Node.js 22.8 or later. The Node tools need no third-party packages.

```sh
npm run check
npm run sync -- --output dist/ecosystem-sync.json
npm run validate:payload -- --bundle dist/ecosystem-sync.json
```

`npm run check` runs the tests, verifies the 25 imported artifact hashes and policy settings, and scans working-tree text files for known credential patterns. The generated synchronization bundle contains sorted source paths, byte counts, SHA-256 hashes, and the configured destination.

## Synchronize source files

The default operation writes a local bundle. Destination and size limits are configured in [gateway-policies.json](config/gateway-policies.json).

An explicit push requires a GitHub token with repository contents write access and the current remote branch head. Workflow changes also require the token's workflow permission. Set `GH_TOKEN` or `GITHUB_TOKEN` through your environment or secret manager, then run:

```sh
npm run sync -- --push --expected-head CURRENT_FULL_REMOTE_COMMIT_SHA
```

The tool checks the expected head before creating a commit, preserves unrelated remote files, checks the head again, and updates the branch with `force: false`. A forward or divergent branch change is rejected by GitHub. GitHub's ref API does not offer an atomic expected-head compare-and-swap; a concurrent backward reset can occur after the final read. Coordinate branch resets while synchronizing. It rejects unsafe paths, symlinks, invalid UTF-8, credential patterns, tampered artifact metadata, and payloads above the configured size limits. It updates included files and preserves unrelated remote files.

Cloud Build source snapshots may omit `.git`. [cloudbuild.yml](examples/deployment/cloudbuild.yml) uses the explicit `--snapshot` mode to run checks and create a local bundle from that workspace. Remote publication uses the separate explicit push command.

## SEO agent integration

Use the optional [seo-agent](https://github.com/emptyncrypt-hue/seo-agent) Cloudflare Worker through Ecosystem's dependency-free control client. Set `SEO_AGENT_URL` to your deployed Worker's HTTPS origin and provide its `AGENT_TOKEN` as `SEO_AGENT_TOKEN` through your environment or secret manager, then run:

```sh
npm run seo -- status
npm run seo -- findings
npm run seo -- proposals
```

Run, approve, reject, and revert operations require explicit commands. Leave the Worker's `AUTO_APPLY_FIELDS` empty to require approval for site changes. [Setup, deployment prerequisites, and command reference](docs/seo-agent.md) explain how to connect the separate Worker and the public site's injector. No live deployment or site connection is included.

## Configuration and documentation

- [Integration verification and deployment prerequisites](docs/integration_verification.md)
- [Documents and source index](docs/README.md)
- [Imported-source provenance and current hashes](docs/source_manifest.json)
- [CMEK organization policy setup](config/README.md)
- [Active verification workflow](.github/workflows/verify.yml)
- [Node ACL contract](contracts/node_acl_smart_contract.sol)

The active workflow runs integration tests, builds and verifies a sync bundle, parses configuration files, generates a DOCX blueprint, compiles the ACL contract, and validates the pinned Terraform provider configuration.

Generate a blueprint with Python and the pinned document dependency:

```sh
python -m pip install -r requirements.txt
python scripts/generate_blueprint.py --output generated/Dune-sub_Framework_Blueprint.docx
```

The imported archives preserve their original architecture and deployment reports. Repository synchronization covers source files in GitHub; physical-node attestation, mTLS transport, blockchain deployment, and live cloud policy enforcement require their respective services and credentials. The credential scanner covers current text files and documented patterns; Git history and generated/tooling directories are excluded.
