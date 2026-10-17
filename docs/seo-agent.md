# SEO agent service

Ecosystem includes the Cloudflare Worker in [`services/seo-agent`](../services/seo-agent), including its API, dashboard, sitemap crawler, AI drafting pipeline, database schema, tests, and optional site injector. The upstream MIT license is retained. [`UPSTREAM.json`](../services/seo-agent/UPSTREAM.json) records the imported revision, original file hashes, and integration changes.

The service is configured for `https://dunesub.de` in [`config/seo-agent.json`](../config/seo-agent.json), using Cloudflare account `c01bd8dd02ec6b1dd3a05ea21649d1b8`. The control Worker is named `dunesub-seo-agent`. Its API and dashboard use a `workers.dev` URL assigned by Cloudflare; that URL is separate from the public site being audited.

## Verify locally

Use Node.js 24 for the SEO service. The existing dependency-free Ecosystem tools continue to support their documented Node.js version. From the repository root:

```sh
npm run check
npm run seo:install
npm run seo:verify
```

The SEO verification checks the recorded source hashes, generates local configuration and Worker types, checks TypeScript, runs the upstream tests, builds the Worker, and runs it in a local Cloudflare runtime. The runtime smoke test exercises authenticated HTTP requests, proposal approval and rejection, D1 journal writes, KV overrides, and rollback. It makes no website or AI requests and needs no Cloudflare token.

`npm run seo:configure` generates the gitignored `services/seo-agent/wrangler.jsonc` from the repository's non-secret site configuration. Resource placeholders support local verification. Cloud deployment provisions real resources before using that configuration. `npm run seo:dev` opens the local dashboard through Wrangler; a crawl or AI draft additionally needs the services it invokes.

## Deploy from GitHub Actions

Create the GitHub environment `seo-production` and configure two environment secrets:

| Secret | Purpose |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | A Cloudflare-issued token authorized to manage the configured account's Workers, D1, KV, Queues, and Workers AI resources. Scope it to the intended account. |
| `AGENT_TOKEN` | A separate strong random token for dashboard and API access. Generate and retain it in your secret manager. |

The account ID is already in the site configuration. An account ID identifies the account; `CLOUDFLARE_API_TOKEN` authorizes deployment. The application uses `AGENT_TOKEN` to authorize operations after deployment. These values serve different purposes.

Once the workflow is on the repository's default branch, manually run **Deploy DuneSub SEO agent** from GitHub Actions. The workflow installs pinned tooling, verifies the repository and Worker, provisions or reuses the named D1 database, KV namespace, and drafting queue, applies the idempotent SQL schema, deploys the Worker, and checks its authenticated status endpoint.

Deployment supplies `AGENT_TOKEN` with the Worker upload through a short-lived secret file outside the repository. The file is removed after the command. The client never accepts credentials in site configuration or command-line arguments. Credentials belong in environment secret bindings, and their values must stay out of source files, commits, and logs.

Repository scanning and synchronization also reject local `.dev.vars` secret files and suffix variants, including in source snapshots. The empty `.dev.vars.example` template is allowed. Local type checking uses declared secret types and requires no secret file.

## Deploy from this workspace

The same deployment can run from a shell where both secrets have been provided through its environment:

```sh
npm run seo:install
npm run seo:verify
npm run seo:deploy
npm run seo:status
```

The deploy and status commands use Node's environment proxy support, preserving the workspace's proxy and CA trust. A missing credential fails before provisioning. Resource lookups use the dedicated names in the site configuration, allowing later deployments to reuse those resources. A failed mutation is reported for inspection rather than automatically retried.

The status command verifies the deployed Worker and calls its authenticated `/status` endpoint. Open the reported Worker URL and use `AGENT_TOKEN` in the dashboard login. Start the first crawl explicitly, then review findings and proposals. AI drafting runs on a separate queue, so proposals may arrive after a crawl finishes.

## Apply changes to the public site

The Worker can audit the public site's sitemap and prepare proposals once deployed. The site's serving Worker must also read the same KV namespace before approved changes affect delivered HTML. `AUTO_APPLY_FIELDS` stays empty, so site metadata changes require explicit proposal approval.

For a site already served by a Worker, merge `override:<pathname>` values into its computed title and description using the upstream injector contract. Preserve its existing metadata when KV is missing or unavailable. For another origin behind Cloudflare, the included [`injector/`](../services/seo-agent/injector) provides a proxy Worker.

The proxy injector needs the actual origin host and zone route. Identify the origin before routing `dunesub.de/*` through it; using `dunesub.de` as both its route and origin creates a proxy loop. Deploying the control Worker does not install that site route.

## Provenance and current state

The Worker is imported from `emptyncrypt-hue/seo-agent` at commit `a145d2677ae1882680a828e196deb14b3b618955`. The integration repairs the upstream clean-install lockfile and declares secret types without requiring a local secret file. Application behavior remains upstream behavior.

The existing 25 imported framework artifacts and their provenance manifest remain intact. This integration does not depend on unverified `Secrets-Vault.d`, `Dune-Sub.d`, or evaluator modules. A vault can supply environment bindings when its actual implementation and connection are available.

Local verification establishes that the service builds and its local storage/API integration works. A live deployment is established by the deploy command and its authenticated status check; a public-site connection additionally requires the injector verification above.

On 2026-10-17, a direct check of `https://dunesub.de/sitemap.xml` returned HTTP 401 and a Squarespace **Private Site** HTML page. The upstream crawler needs a publicly readable XML sitemap. Make the intended site and its sitemap accessible before expecting successful audits; no site visibility settings were changed by this integration.
