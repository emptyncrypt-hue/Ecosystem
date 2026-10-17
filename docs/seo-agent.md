# SEO agent integration

Ecosystem provides a dependency-free Node.js control client for a separately deployed [emptyncrypt-hue/seo-agent](https://github.com/emptyncrypt-hue/seo-agent) Cloudflare Worker. It reads findings and proposals, starts crawls, and sends explicit approval, rejection, and revert requests. It adds no Node dependencies, submodules, or vendored upstream code; the upstream MIT license remains with the separate checkout. Imported source archives and their manifest are unchanged.

The REST contract was reviewed at upstream commit [`a145d2677ae1882680a828e196deb14b3b618955`](https://github.com/emptyncrypt-hue/seo-agent/tree/a145d2677ae1882680a828e196deb14b3b618955). The integration is tested with a local mock API. No Worker has been deployed or verified against a live site; the public site URL and Cloudflare credentials must be supplied for deployment.

## Connect Ecosystem

Use Node.js 22.8 or later. Ecosystem needs no package installation for this client. Set `SEO_AGENT_URL` to the control Worker's origin, such as `https://seo-agent.your-subdomain.workers.dev`. This is separate from the public site that the Worker crawls.

Supply `SEO_AGENT_TOKEN` through your process environment or secret manager. Its value must match the Worker's `AGENT_TOKEN` secret. In Bash, an existing token can be entered without printing it or recording it in shell history:

```sh
read -rs -p 'SEO agent token: ' SEO_AGENT_TOKEN
printf '\n'
export SEO_AGENT_TOKEN
export SEO_AGENT_URL='https://seo-agent.your-subdomain.workers.dev'
npm run seo -- status
```

Do not put the token in a command argument, URL, JSON configuration, or file inside Ecosystem. There is no token CLI option. The repository's credential checks also reject sensitive environment files.

The default [configuration](../config/seo-agent.json) is intentionally disconnected:

```json
{
  "version": 1,
  "url": "",
  "timeoutMs": 15000
}
```

Set `url` to the deployed origin, or use `SEO_AGENT_URL`, which takes precedence. Select another configuration with `--config PATH`. Use an origin only, without a path, query, fragment, or embedded credentials. Remote connections require HTTPS; plain HTTP is accepted only for loopback local development, for example `http://127.0.0.1:8787`.

## Commands

Run `npm run seo -- --help` for usage. After linking or installing the package, `ecosystem-seo` exposes the same commands. Omitting a command selects `status`. Successful responses are printed as JSON.

| Command after `npm run seo --` | Upstream request | Purpose |
| --- | --- | --- |
| `status` | `GET /status` | Latest run, running state, findings and proposal counts |
| `findings [--status open\|resolved\|dismissed]` | `GET /findings?status=...` | Findings; default `open` |
| `proposals [--status proposed\|approved\|rejected\|reverted]` | `GET /proposals?status=...` | Proposals; default `proposed` |
| `changes` | `GET /changes` | Applied and reverted change journal |
| `overrides` | `GET /overrides` | Current KV overrides |
| `analytics` | `GET /analytics/summary` | Search, AI traffic, and change metrics where configured |
| `run` | `POST /run` | Start a pipeline run |
| `approve --id N` | `POST /proposals/N/approve` | Apply a reviewed proposal through KV |
| `reject --id N` | `POST /proposals/N/reject` | Reject a proposal |
| `revert --id N` | `POST /changes/N/revert` | Revert a change, using its change ID |

`--config PATH` is available for every command. IDs are positive integers. Review proposals before approving them; a proposal ID and a change ID refer to different records. The client makes no automatic approval or revert decisions.

Upstream list responses are capped at 500 findings and 200 proposals or changes, with no pagination in these endpoints. They are operational views, not complete historical exports.

`run` returns HTTP 202 when the background pipeline starts. Poll with `npm run seo -- status` until `running` is false and `lastRun` advances, then inspect findings and proposals. AI drafts are processed by a separate queue and may arrive later. HTTP 409 means a run is already in progress; the CLI exits unsuccessfully and does not retry. Poll status instead. Other HTTP errors, invalid configuration, and request timeouts also produce a nonzero exit; after an uncertain mutating request, inspect the remote state before repeating it.

Keep the separate Worker's `AUTO_APPLY_FIELDS` empty: if an operator enables automatic fields there, a triggered or scheduled run can apply matching proposals without another approval command.

## Deploy the separate Worker

Deployment requires a Cloudflare account on Workers Paid, Node.js 18 or later for the upstream project, Wrangler 4 or later, D1, KV, Queues, Workers AI, and a real public site serving `sitemap.xml`. Ecosystem itself still requires Node.js 22.8 or later. Deploy the upstream project outside this repository:

```sh
git clone https://github.com/emptyncrypt-hue/seo-agent.git
cd seo-agent
git checkout a145d2677ae1882680a828e196deb14b3b618955
npm ci
npx wrangler login
npx wrangler d1 create seo-agent-db
npx wrangler kv namespace create SEO_OVERRIDES
npx wrangler queues create seo-agent-drafts
cp wrangler.example.jsonc wrangler.jsonc
cp .dev.vars.example .dev.vars
```

Keep these files in the separate upstream checkout. The copied `.dev.vars` template contains empty secret entries for local tooling; store production secrets with Wrangler. Edit `wrangler.jsonc`: fill in the D1 database ID and KV namespace ID, retain the `DB`, `OVERRIDES`, `AI`, and `DRAFT_QUEUE` bindings, and set `SITE_URL` to the actual public site's origin. Set the site profile as appropriate and keep `AUTO_APPLY_FIELDS` set to `""`. Optional Google Search Console and citation integrations can stay disabled.

Generate and retain a strong token in your secret manager. Enter that value with the hidden Bash prompt above, then, from the upstream checkout, upload it without printing it:

```sh
printf '%s' "$SEO_AGENT_TOKEN" | npx wrangler secret put AGENT_TOKEN
npm run db:init
npm run deploy
```

`db:init` applies upstream `schema.sql` to the remote D1 database; rerun it when upgrading upstream. Use the deployed Worker's HTTPS origin as Ecosystem's `SEO_AGENT_URL`, and use the same token as `SEO_AGENT_TOKEN`. Run `status` first, then explicitly run `run` and poll status. Keep credentials out of logs and repository files.

## Connect the public site's injector

Ecosystem contains repository tools and framework documents; it does not host a public website. The injector belongs on the public site configured by `SITE_URL`. Crawling and review can run independently, but approved KV overrides affect served HTML only after the site's injector is connected.

For an existing site Worker, follow the upstream [injector contract](https://github.com/emptyncrypt-hue/seo-agent/tree/a145d2677ae1882680a828e196deb14b3b618955#connecting-your-site-the-injector-side): bind the agent's same KV namespace as `SEO_OVERRIDES`, read `override:<pathname>`, and merge permitted `title` and `description` fields over the site's computed metadata. KV misses, malformed values, and read errors must leave the computed metadata available. Cache TTL means approved changes may take time to appear.

For another origin behind Cloudflare, upstream supplies a proxy Worker. In its separate checkout:

```sh
cp injector/wrangler.example.jsonc injector/wrangler.jsonc
```

Configure that file with the public site route, the shared KV namespace ID, and an `ORIGIN_HOST` different from the public route host to avoid a proxy loop. Deploy with `npx wrangler deploy -c injector/wrangler.jsonc` when ready to change the site's serving route. Verify the public page's returned HTML before and after an explicitly approved proposal, then inspect `changes` and `overrides`. `revert --id N` uses the change ID to restore the recorded previous field value, or remove the field override if there was no previous value, and retire the proposal. Only the latest unreverted change for a given path and field can be reverted. Consult the journal and served HTML to confirm the result.
