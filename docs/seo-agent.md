# SEO agent service

Ecosystem includes the Cloudflare Worker in [`services/seo-agent`](../services/seo-agent), including its API, dashboard, sitemap crawler, AI drafting pipeline, database schema, tests, and optional site injector. The upstream MIT license is retained. [`UPSTREAM.json`](../services/seo-agent/UPSTREAM.json) records the imported revision, original file hashes, and integration changes.

The service is configured for the canonical origin `https://www.dunesub.de` in [`config/seo-agent.json`](../config/seo-agent.json), using Cloudflare account `c01bd8dd02ec6b1dd3a05ea21649d1b8`. The apex domain redirects to this origin. The control Worker is named `dunesub-seo-agent`. Its API and dashboard use a `workers.dev` URL assigned by Cloudflare; that URL is separate from the public site being audited.

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

For this Squarespace site, use the maintained [`services/seo-injector`](../services/seo-injector) route Worker. It calls `fetch(request)` with the original public hostname, method, body, and cookies, so Squarespace continues to select the correct site. Cloudflare routes send this subrequest to the origin in the zone's DNS records without invoking the same route again. This behavior applies to a **Worker route**, not a Worker Custom Domain. No alternate Squarespace origin hostname is required. See [Cloudflare route behavior and prerequisites](https://developers.cloudflare.com/workers/configuration/routing/routes/).

The injector reads the deployed control Worker's `OVERRIDES` namespace as `SEO_OVERRIDES`. It applies approved title and description values to existing metadata tags in successful GET HTML responses. Redirects, assets, sitemap, robots, authorization errors, cookies, forms, canonical links, and structured data keep their original behavior. It never retries an origin request when metadata processing fails. Markdown probing is not enabled for Squarespace.

Uncompressed, gzip, and Brotli HTML can be rewritten within a 2 MiB decoded-body limit and a two-second processing deadline. Other content encodings and responses exceeding these limits pass through unchanged.

### Publish the Squarespace site

Squarespace must serve a public XML sitemap for audits. In the intended site's **Site Availability** panel, choose **Public** and save. A paid website subscription is required; trial sites and domain parking pages do not provide a sitemap. A homepage that says “Coming Soon” does not establish that a published website exists. See [Squarespace publication](https://support.squarespace.com/hc/en-us/articles/360002088548-Publish-or-hide-your-site) and [sitemap availability](https://support.squarespace.com/hc/en-us/articles/206543547-View-your-site-map).

Verify that `/sitemap.xml` returns XML with public URLs and that `robots.txt` permits crawling. If Squarespace uses `www.dunesub.de` as its canonical origin, align `config/seo-agent.json` with that verified origin before redeploying the control Worker; the crawler filters sitemap URLs by the configured origin. The injector preserves site access controls rather than replacing a blocked sitemap or serving private content.

### Activate Cloudflare and connect the route

The full Cloudflare zone must be **active**, and its website records must be proxied. Preserve all existing DNS records, including mail, verification, and any other subdomains, before changing nameservers at the registrar. The deployment CLI reports the assigned Cloudflare nameservers and checks the website records against Squarespace's current targets. Changing a zone's desired configuration alone does not change its authoritative nameservers.

Required token access includes zone read, DNS read, Workers route write, Workers script write, and access to the control Worker's settings and KV binding. DNS edit is needed when enabling the orange-cloud proxy for existing Squarespace website records. Keep credentials in environment bindings; no credentials belong in this configuration.

```sh
npm run seo:injector:status
npm run seo:injector:build
npm run seo:injector:smoke
npm run seo:injector:deploy
```

The deployment command validates the active zone, expected proxied apex and `www` records, existing route conflicts, and the control Worker's shared KV before changing generated configuration or publishing. It installs only `dunesub.de/*` and `www.dunesub.de/*` for `dunesub-seo-injector`; the authenticated dashboard remains on its separate `workers.dev` hostname. The injector has no public `workers.dev` endpoint and is not a Worker Custom Domain. Local builds use placeholder IDs and cannot establish a live connection.

Once it is on the default branch, the manual [Connect DuneSub website to SEO agent](../.github/workflows/connect-seo-website.yml) workflow runs the same checks and deployment using the `seo-production` environment's `CLOUDFLARE_API_TOKEN`. It does not require the dashboard token.

After deployment, verify the homepage, a public nested page, sitemap, assets, redirects, and form handling. An approved test override can then confirm the shared-KV path; remove or revert it after verification. Keep `AUTO_APPLY_FIELDS` empty until a separate decision authorizes automatic changes.

## Provenance and current state

The Worker is imported from `emptyncrypt-hue/seo-agent` at commit `a145d2677ae1882680a828e196deb14b3b618955`. The integration repairs the upstream clean-install lockfile and declares secret types without requiring a local secret file. Application behavior remains upstream behavior.

The existing 25 imported framework artifacts and their provenance manifest remain intact. This integration does not depend on unverified `Secrets-Vault.d`, `Dune-Sub.d`, or evaluator modules. A vault can supply environment bindings when its actual implementation and connection are available.

Local verification establishes that the service builds and its local storage/API integration works. A live deployment is established by the deploy command and its authenticated status check; a public-site connection additionally requires the injector verification above.

On 2026-10-17, a direct check of `https://dunesub.de/sitemap.xml` returned HTTP 401 and a Squarespace **Private Site** HTML page. The upstream crawler needs a publicly readable XML sitemap. Make the intended site and its sitemap accessible before expecting successful audits; no site visibility settings were changed by this integration.

On 2026-10-18, the control Worker was deployed and its authenticated status verified at `https://dunesub-seo-agent.plamen-r-mihaylov.workers.dev`. The website connection check found the Cloudflare full zone pending, Google Domains authoritative nameservers, DNS API HTTP 403, a Squarespace “Coming Soon” homepage, sitemap HTTP 401, and a robots file blocking all crawlers. These are recorded observations, not evidence that the website connection is active.

After the owner connected the published Squarespace site `sepia-carnation-yj5e.squarespace.com`, fresh checks showed the apex redirecting to `https://www.dunesub.de`, a public homepage, a readable XML sitemap, and a robots file permitting general crawling. The control configuration follows that canonical `www` origin. The XML sitemap initially retained its old built-in Squarespace URL after the domain change; verify its `<loc>` values have refreshed before starting the first crawl. Website publication and the optional Cloudflare metadata-injector connection are separate prerequisites.
