# SEO agent service

Ecosystem includes the Cloudflare Worker in [`services/seo-agent`](../services/seo-agent), including its API, dashboard, sitemap crawler, AI drafting pipeline, database schema, tests, and optional site injector. The upstream MIT license is retained. [`UPSTREAM.json`](../services/seo-agent/UPSTREAM.json) records the imported revision, original file hashes, and integration changes.

The service is configured for the canonical origin `https://www.dunesub.de` in [`config/seo-agent.json`](../config/seo-agent.json), using Cloudflare account `c01bd8dd02ec6b1dd3a05ea21649d1b8`. The apex domain redirects to this origin. The control Worker is named `dunesub-seo-agent`. Its API and dashboard use a `workers.dev` URL assigned by Cloudflare; that URL is separate from the public site being audited.

The dashboard supports [passkey authentication on iOS, Android, Windows and macOS](cross-platform-authentication.md), with bearer-token recovery and existing REST/MCP automation.

## Verify locally

Use Node.js 24 for the SEO service. The existing dependency-free Ecosystem tools continue to support their documented Node.js version. From the repository root:

```sh
npm run check
npm run seo:install
npm run seo:verify
```

The SEO verification checks the recorded source hashes, generates local configuration and Worker types, checks TypeScript, runs the upstream tests, builds the Worker, and runs it in a local Cloudflare runtime. The runtime smoke test exercises authenticated HTTP requests, proposal approval and rejection, D1 journal writes, KV overrides, and rollback. It makes no website or AI requests and needs no Cloudflare token.

`npm run seo:configure` generates the gitignored `services/seo-agent/wrangler.jsonc` from the repository's non-secret site configuration. Resource placeholders support local verification. Cloud deployment provisions real resources before using that configuration. `npm run seo:dev` opens a local dashboard preview through Wrangler. For an interactive token-only localhost preview, use a separate test configuration with `authOrigin` omitted and a synthetic agent token; the production authentication origin deliberately does not authorize localhost. The native verification suite exercises configured HTTPS passkey ceremonies without a browser or production credentials. A crawl or AI draft additionally needs the services it invokes.

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

The injector reads the deployed control Worker's `OVERRIDES` namespace as `SEO_OVERRIDES`. On ordinary pages it updates existing title and description tags in successful GET HTML. On the verified homepage paths `/`, `/home`, and `/home/`, it presents the approved DuneSub Ecosystem homepage and uses the canonical `override:/` metadata. The Squarespace CMS source remains intact. Redirects, authorization errors, privacy gates, non-HTML formats, editor/preview requests, cookies, and form submissions retain their origin behavior, and origin requests are never replayed. The public sitemap normalizes only known site origins and homepage aliases to the canonical URL; unrelated sitemap locations remain unchanged. Markdown probing is not enabled for Squarespace.

Uncompressed, gzip, and Brotli HTML can be rewritten within a 2 MiB decoded-body limit and a two-second processing deadline. Other content encodings and responses exceeding these limits pass through unchanged.

### Publish the Squarespace site

Squarespace must serve a public XML sitemap for audits. In the intended site's **Site Availability** panel, choose **Public** and save. A paid website subscription is required; trial sites and domain parking pages do not provide a sitemap. A homepage that says “Coming Soon” does not establish that a published website exists. See [Squarespace publication](https://support.squarespace.com/hc/en-us/articles/360002088548-Publish-or-hide-your-site) and [sitemap availability](https://support.squarespace.com/hc/en-us/articles/206543547-View-your-site-map).

Verify that `/sitemap.xml` returns XML with public URLs and that `robots.txt` permits crawling. `config/seo-agent.json` follows the verified canonical origin `https://www.dunesub.de`. Squarespace's sitemap can retain its built-in hostname after connecting a domain. The optional `sitemapOriginAliases` list explicitly identifies verified HTTPS origins whose sitemap locations should be mapped to the configured canonical origin. This deployment lists only `https://sepia-carnation-yj5e.squarespace.com`. Paths and queries are preserved, and both child sitemaps and pages are fetched from `www.dunesub.de`; aliases are never fetch destinations. Other origins, credentialed URLs, and lookalike hosts are rejected, and sitemap redirects are not followed. The list is limited to five origins and defaults to no aliases. The site injector additionally normalizes the known public sitemap hostname and homepage path aliases, so search engines receive the canonical homepage URL as well.

The injector preserves site access controls rather than replacing a blocked sitemap or serving private content. The homepage presentation additionally checks for noindex and known password-page markers before replacing successful HTML.

### Activate Cloudflare and connect the route

The full Cloudflare zone must be **active**, and its website records must be proxied. Preserve all existing DNS records, including mail, verification, and any other subdomains, before changing nameservers at the registrar. The deployment CLI reports the assigned Cloudflare nameservers and checks the website records against Squarespace's current targets. Changing a zone's desired configuration alone does not change its authoritative nameservers.

For a nameserver migration, stage the website records as DNS-only while Cloudflare activation and its edge certificate are pending. Confirm Universal SSL is enabled, an active certificate covers both apex and `www`, and the origin uses compatible HTTPS settings before enabling the proxy. These TLS checks are operational prerequisites; the deployment CLI does not perform them. Its route status means no conflicts were found, so independently verify the actual installed routes after deployment.

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

### Homepage, social image, and approvals

The approved baseline title is `DuneSub Ecosystem | Policy Tools & SEO Automation`. The homepage description is `DuneSub Ecosystem combines policy tools, Cloudflare SEO automation, and verified integrations with approvals for metadata changes.` The same factual description is supplied as `siteDescription` in `config/seo-agent.json` for future AI drafting. `homepagePathAliases` explicitly maps `/home` to the root for crawl discovery, new proposals, and comparison with prior snapshots; unrelated canonical checks remain strict. Historical proposal and change rows keep their original paths.

The homepage is served at the Cloudflare edge after a successful normal Squarespace origin response. It contains platform content and source links, not the prior blogging/shop template. No Squarespace editor credentials are available in this deployment, so the CMS source is unchanged; rolling back the site Worker restores that source presentation. Other Squarespace pages remain under their existing origin behavior. The stylesheet is served at `/__dunesub/platform.css`.

The generated sharing image is an external deployment asset: 1730×909 PNG, 1,529,576 bytes, SHA-256 `ad01c8e2e113fba86ca3901e6bc019601716c50fe091f788b7c6699ce744ffbc`. Its manifest is checked in at `services/seo-injector/src/social-image.json`; its bytes live in the shared KV under `asset:dunesub-social:<sha256>.png`. Upload and verify the exact reviewed PNG before publishing a manifest referring to it. The Worker serves only its exact versioned URL `/__dunesub/social/<sha256>.png`, with PNG/dimension/hash verification and immutable caching. The PNG is retained as a deployment artifact rather than included in the text-only source synchronization bundle.

The user's explicit approval of the suggested title/description is applied through normal proposal creation and approval, preserving the D1 change journal. The previous generic `/home` description can be retired through its journaled revert after canonical metadata is in place. Future automatic metadata application remains disabled. The pipeline must verify the canonical homepage, its alias, sitemap, stylesheet and exact social image bytes before declaring the findings fixed.

`llms.txt` remains optional. Its absence is informational, following [Google's guidance](https://developers.google.com/search/docs/fundamentals/ai-optimization-guide); existing open findings refresh their severity and detail on subsequent runs. No `llms.txt` content is fabricated merely to clear a warning. The separately requested [internal encrypted context](internal-llms.md) is served only through the authenticated control Worker. Public context-file routes remain unavailable, and the private document does not clear the public informational finding.

## Provenance and current state

The Worker is imported from `emptyncrypt-hue/seo-agent` at commit `a145d2677ae1882680a828e196deb14b3b618955`. The integration repairs the upstream clean-install lockfile and declares secret types without requiring a local secret file. Its crawler additionally supports explicit sitemap origin and homepage path aliases and validates exact origins before fetching. The integration supplies factual drafting context, normalizes new homepage proposals, and refreshes persistent finding severity without reopening dismissed findings. Original and modified source hashes remain separately recorded in the provenance manifest.

The existing 25 imported framework artifacts and their provenance manifest remain intact. This integration does not depend on unverified `Secrets-Vault.d`, `Dune-Sub.d`, or evaluator modules. A vault can supply environment bindings when its actual implementation and connection are available.

The deployed control Worker is `https://dunesub-seo-agent.plamen-r-mihaylov.workers.dev`. Cloudflare's full `dunesub.de` zone is active with `frank.ns.cloudflare.com` and `reza.ns.cloudflare.com`. Universal SSL covers the apex and `www`; the four Squarespace apex A records and `www` CNAME are proxied. Both exact public-site routes are assigned to `dunesub-seo-injector`, and both Workers share the same overrides namespace. Verification and mail-related DNS records are retained.

The first successful audit covered the public homepage and reported a missing description, a homepage alias/canonical mismatch, a missing sharing image, and missing optional `llms.txt`. The owner approved the platform copy and requested the fixes described above. After publishing these changes, run a fresh audit and check its actual findings, run status, deployed routes, and public responses. Source verification and local tests alone do not establish a successful deployment or audit.
