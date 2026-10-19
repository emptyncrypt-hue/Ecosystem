#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateInternalLlmsSecrets } from './internal-llms.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const API = 'https://api.cloudflare.com/client/v4';
const LOCAL_D1_ID = '00000000-0000-0000-0000-000000000000';
const LOCAL_KV_ID = '00000000000000000000000000000000';
const NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const HEX_ID = /^[a-f0-9]{32}$/i;

export function validateConfig(input) {
  const keys = ['siteUrl', 'siteName', 'siteDescription', 'accountId', 'workerName', 'databaseName', 'queueName', 'namespaceTitle', 'sitemapOriginAliases', 'homepagePathAliases'];
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).some(key => !keys.includes(key))) {
    throw new Error('SEO configuration accepts only documented non-secret fields.');
  }
  if (typeof input.accountId !== 'string' || !HEX_ID.test(input.accountId)) throw new Error('A 32-character Cloudflare account ID is required.');
  for (const key of ['workerName', 'databaseName', 'queueName', 'namespaceTitle']) {
    if (typeof input[key] !== 'string' || !NAME.test(input[key])) throw new Error(`Invalid SEO configuration field: ${key}.`);
  }
  let site;
  try { site = new URL(input.siteUrl); } catch { throw new Error('A valid HTTPS site URL is required.'); }
  if (site.protocol !== 'https:' || site.username || site.password || site.search || site.hash || site.pathname !== '/') {
    throw new Error('SITE_URL must be an HTTPS origin without credentials, a path, query, or fragment.');
  }
  if (typeof input.siteName !== 'string' || !input.siteName.trim() || input.siteName.length > 100) {
    throw new Error('A siteName of 1–100 characters is required.');
  }
  if (input.siteDescription !== undefined && (typeof input.siteDescription !== 'string' || !input.siteDescription.trim()
      || input.siteDescription.length > 500 || /[<>\u0000-\u001f\u007f]/.test(input.siteDescription))) {
    throw new Error('siteDescription must be 1–500 characters of single-line plain text.');
  }
  let homepagePathAliases;
  if (input.homepagePathAliases !== undefined) {
    if (!Array.isArray(input.homepagePathAliases) || input.homepagePathAliases.length > 5
        || input.homepagePathAliases.some(path => typeof path !== 'string' || path.length > 200
          || !/^\/(?!\/)[a-zA-Z0-9/_-]+$/.test(path) || path.includes('//'))) {
      throw new Error('homepagePathAliases must contain at most five explicit local paths without queries, fragments, or URL encoding.');
    }
    homepagePathAliases = [...new Set(input.homepagePathAliases)];
  }
  let sitemapOriginAliases;
  if (input.sitemapOriginAliases !== undefined) {
    if (!Array.isArray(input.sitemapOriginAliases) || input.sitemapOriginAliases.length > 5) {
      throw new Error('sitemapOriginAliases must contain at most five HTTPS origins.');
    }
    sitemapOriginAliases = input.sitemapOriginAliases.map(value => {
      let alias;
      try { alias = typeof value === 'string' ? new URL(value) : null; } catch { /* Validated below. */ }
      if (!alias || alias.protocol !== 'https:' || alias.username || alias.password || alias.search || alias.hash || alias.pathname !== '/') {
        throw new Error('sitemapOriginAliases accepts HTTPS origins without credentials, paths, queries, or fragments.');
      }
      return alias.origin;
    });
    sitemapOriginAliases = [...new Set(sitemapOriginAliases)].filter(origin => origin !== site.origin);
  }
  return { ...input, siteUrl: site.origin, ...(sitemapOriginAliases !== undefined ? { sitemapOriginAliases } : {}),
    ...(homepagePathAliases !== undefined ? { homepagePathAliases } : {}) };
}

async function readConfig(rootDir) {
  try { return validateConfig(JSON.parse(await readFile(join(rootDir, 'config/seo-agent.json'), 'utf8'))); }
  catch (error) {
    if (error instanceof SyntaxError || error?.code) throw new Error('Could not read config/seo-agent.json.');
    throw error;
  }
}

export function buildWranglerConfig(config, resources) {
  config = validateConfig(config);
  if (resources && (!UUID.test(resources.databaseId ?? '') || !HEX_ID.test(resources.namespaceId ?? '')
      || resources.databaseId === LOCAL_D1_ID || resources.namespaceId === LOCAL_KV_ID)) {
    throw new Error('Cloudflare returned invalid resource identifiers.');
  }
  return {
    $schema: 'node_modules/wrangler/config-schema.json',
    name: config.workerName,
    account_id: config.accountId,
    main: './src/index.ts',
    compatibility_date: '2025-06-17',
    compatibility_flags: ['nodejs_compat'],
    workers_dev: true,
    observability: { enabled: true },
    upload_source_maps: true,
    triggers: { crons: ['17 6 * * *'] },
    d1_databases: [{ binding: 'DB', database_name: config.databaseName, database_id: resources?.databaseId ?? LOCAL_D1_ID }],
    kv_namespaces: [{ binding: 'OVERRIDES', id: resources?.namespaceId ?? LOCAL_KV_ID }],
    ai: { binding: 'AI' },
    queues: {
      producers: [{ binding: 'DRAFT_QUEUE', queue: config.queueName }],
      consumers: [{ queue: config.queueName, max_batch_size: 1, max_batch_timeout: 5, max_retries: 3 }],
    },
    vars: {
      SITE_URL: config.siteUrl,
      ...(config.sitemapOriginAliases?.length ? { SITEMAP_ORIGIN_ALIASES: config.sitemapOriginAliases.join(',') } : {}),
      ...(config.homepagePathAliases?.length ? { HOMEPAGE_PATH_ALIASES: config.homepagePathAliases.join(',') } : {}),
      SITE_NAME: config.siteName,
      SITE_DESCRIPTION: config.siteDescription ?? '',
      GSC_PROPERTY: `sc-domain:${new URL(config.siteUrl).hostname}`,
      AI_MODEL: '@cf/zai-org/glm-4.7-flash',
      AUTO_APPLY_FIELDS: '',
      MAX_PROPOSALS_PER_RUN: '8',
      TITLE_BRAND_SUFFIX: '',
      SHELL_TITLE: '',
      ARTICLE_PATH_PREFIX: '',
      ARTICLE_API_TEMPLATE: '',
      AEO_CHECKS: 'true',
      AEO_BOT_UA: '',
      CITATION_QUERIES: '',
      CITATION_CRON_DAY: '1',
    },
  };
}

export async function configure({ rootDir = ROOT, resources } = {}) {
  const config = await readConfig(rootDir);
  const generated = buildWranglerConfig(config, resources);
  const notice = resources
    ? '// Generated deployment bindings; resource IDs are intentionally untracked.\n'
    : '// LOCAL PLACEHOLDERS ONLY. Run npm run seo:deploy to provision real bindings.\n';
  try { await writeFile(join(rootDir, 'services/seo-agent/wrangler.jsonc'), notice + JSON.stringify(generated, null, 2) + '\n', { mode: 0o600 }); }
  catch { throw new Error('Could not write the generated Worker configuration.'); }
  return generated;
}

export function requireCredentials(env) {
  const cloudflareToken = env.CLOUDFLARE_API_TOKEN;
  const agentToken = env.AGENT_TOKEN;
  if (typeof cloudflareToken !== 'string' || !cloudflareToken.trim()) {
    throw new Error('Set CLOUDFLARE_API_TOKEN through your external secret manager before deploying or checking status.');
  }
  if (typeof agentToken !== 'string' || !agentToken.trim()) {
    throw new Error('Set a separate AGENT_TOKEN through your external secret manager before deploying or checking status.');
  }
  if (cloudflareToken === agentToken) throw new Error('AGENT_TOKEN must differ from CLOUDFLARE_API_TOKEN.');
  if (/[\r\n]/.test(cloudflareToken) || /[\r\n]/.test(agentToken)) throw new Error('Credential values must not contain line breaks.');
  return { cloudflareToken, agentToken };
}

// Read a bounded response even when Content-Length is absent or dishonest.
// The request's AbortSignal also bounds a real network stream; this local timer
// handles supplied fetch implementations and stalled body readers.
async function boundedJson(response) {
  const limit = 1_048_576;
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Missing response body.');
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; void reader.cancel().catch(() => {}); }, 30_000);
  const chunks = [];
  let total = 0;
  try {
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > limit) throw new Error('Response too large.');
    while (true) {
      const { done, value } = await reader.read();
      if (timedOut) throw new Error('Response timed out.');
      if (done) break;
      total += value.byteLength;
      if (total > limit) throw new Error('Response too large.');
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
  } finally {
    clearTimeout(timer);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export class CloudflareClient {
  constructor(accountId, token, fetchImpl = globalThis.fetch) {
    if (typeof accountId !== 'string' || !HEX_ID.test(accountId)) throw new Error('Invalid Cloudflare account ID.');
    this.base = `${API}/accounts/${accountId}`;
    this.token = token;
    this.fetch = fetchImpl;
  }

  async request(path, method = 'GET', body) {
    if (!/^\/[a-z0-9/_-]+(?:\?[a-z0-9_=&%-]+)?$/i.test(path)) throw new Error('Invalid Cloudflare API path.');
    let response;
    try {
      response = await this.fetch(this.base + path, {
        method,
        headers: { Authorization: `Bearer ${this.token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
        redirect: 'error',
        signal: AbortSignal.timeout(30_000),
      });
    } catch { throw new Error(`Cloudflare ${method} request failed; no automatic retry was performed.`); }
    let data;
    try { data = await boundedJson(response); } catch { throw new Error('Cloudflare returned an unreadable response.'); }
    if (!response.ok || data?.success !== true) {
      throw new Error(`Cloudflare ${method} request failed (HTTP ${response.status}); check token permissions and account settings. No automatic retry was performed.`);
    }
    return data;
  }

  async find(path, field, value) {
    const matches = [];
    let seen = 0;
    for (let page = 1; page <= 20; page++) {
      const data = await this.request(`${path}?page=${page}&per_page=100`);
      const entries = Array.isArray(data.result) ? data.result : data.result?.queues;
      if (!Array.isArray(entries)) throw new Error('Cloudflare returned an invalid resource list.');
      seen += entries.length;
      matches.push(...entries.filter(entry => entry[field] === value));
      if (matches.length > 1) throw new Error('Multiple Cloudflare resources share the configured name; resolve this before deployment.');
      const info = data.result_info;
      // Endpoints may cap or ignore the requested per_page. Explicit totals
      // take precedence over a short page; scan every page to detect duplicate
      // titles as well as reuse a resource found after the first page.
      const totalPages = Number.isInteger(info?.total_pages) && info.total_pages >= 0 ? info.total_pages : null;
      const totalCount = Number.isInteger(info?.total_count) && info.total_count >= 0 ? info.total_count : null;
      const complete = totalPages !== null ? page >= totalPages
        : totalCount !== null ? seen >= totalCount : entries.length === 0;
      if (complete) return matches[0] ?? null;
    }
    throw new Error('Cloudflare resource lookup exceeded 20 pages; narrow the account resources before deploying.');
  }

}

export async function ensureResources(client, config) {
  // Exact-name GET before POST makes reruns reuse existing resources. Mutations
  // are never retried: after an uncertain response, rerun to list by name again.
  let database = await client.find('/d1/database', 'name', config.databaseName);
  if (!database) database = (await client.request('/d1/database', 'POST', { name: config.databaseName })).result;
  if (!UUID.test(database?.uuid ?? '') || database.uuid === LOCAL_D1_ID) throw new Error('Cloudflare returned an invalid D1 identifier.');

  let namespace = await client.find('/storage/kv/namespaces', 'title', config.namespaceTitle);
  if (!namespace) namespace = (await client.request('/storage/kv/namespaces', 'POST', { title: config.namespaceTitle })).result;
  if (!HEX_ID.test(namespace?.id ?? '') || namespace.id === LOCAL_KV_ID) throw new Error('Cloudflare returned an invalid KV identifier.');

  let queue = await client.find('/queues', 'queue_name', config.queueName);
  if (!queue) queue = (await client.request('/queues', 'POST', { queue_name: config.queueName })).result;
  if (!HEX_ID.test(queue?.queue_id ?? '')) throw new Error('Cloudflare returned an invalid queue identifier.');
  return { databaseId: database.uuid, namespaceId: namespace.id };
}

export async function withSecretsFile(secrets, action) {
  const directory = await mkdtemp(join(tmpdir(), 'ecosystem-seo-secrets-'));
  try {
    await chmod(directory, 0o700);
    const filename = join(directory, 'secrets.json');
    await writeFile(filename, JSON.stringify(secrets), { mode: 0o600, flag: 'wx' });
    return await action(filename);
  } finally { await rm(directory, { recursive: true, force: true }); }
}

export async function runWrangler(args, { rootDir = ROOT, env = process.env, accountId } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'ecosystem-wrangler-'));
  try {
    await chmod(directory, 0o700);
    const configHome = join(directory, 'config');
    const cacheHome = join(directory, 'cache');
    await mkdir(join(configHome, '.wrangler'), { recursive: true, mode: 0o700 });
    await mkdir(join(cacheHome, '.wrangler'), { recursive: true, mode: 0o700 });
    // Inherit the session proxy and CA trust. Suppress persistent diagnostic
    // logs, and never stream child output which can contain credential values.
    const childEnv = { ...env, CLOUDFLARE_ACCOUNT_ID: accountId, WRANGLER_SEND_METRICS: 'false',
      WRANGLER_LOG_PATH: join(directory, 'wrangler.log'), XDG_CONFIG_HOME: configHome,
      XDG_CACHE_HOME: cacheHome, CI: 'true' };
    delete childEnv.AGENT_TOKEN;
    delete childEnv.INTERNAL_LLMS_KEY;
    delete childEnv.INTERNAL_LLMS_CIPHERTEXT;
    const binary = join(rootDir, 'services/seo-agent/node_modules/wrangler/bin/wrangler.js');
    await new Promise((done, fail) => {
      const stage = args[0] === 'd1' ? 'remote D1 initialization' : args.includes('--dry-run') ? 'local Worker bundle check' : 'Worker publication';
      const child = spawn(process.execPath, [...(Number(process.versions.node.split('.')[0]) >= 24 ? ['--use-env-proxy'] : []), binary, ...args], {
        cwd: join(rootDir, 'services/seo-agent'), env: childEnv, stdio: ['ignore', 'ignore', 'ignore'],
        timeout: 300_000, killSignal: 'SIGKILL',
      });
      child.once('error', () => fail(new Error('Unable to start Wrangler; install service dependencies first.')));
      child.once('close', code => code === 0 ? done() : fail(new Error(`Wrangler ${stage} failed${child.killed ? ' or exceeded five minutes' : ''}; check Cloudflare permissions, plan availability, and Worker configuration. Child output was withheld to protect credentials.`)));
    });
  } finally { await rm(directory, { recursive: true, force: true }); }
}

async function accountWorkerUrl(client, config) {
  const result = (await client.request('/workers/subdomain')).result;
  if (typeof result?.subdomain !== 'string' || !NAME.test(result.subdomain)) {
    throw new Error('Configure a workers.dev subdomain in your Cloudflare account before deploying.');
  }
  return `https://${config.workerName}.${result.subdomain}.workers.dev`;
}

async function verifyWorker(url, agentToken, fetchImpl, attempts = 1) {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const response = await fetchImpl(`${url}/status`, {
        headers: { Authorization: `Bearer ${agentToken}` }, redirect: 'error', signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok) { await response.body?.cancel(); throw new Error(); }
      const data = await boundedJson(response);
      if (!data || typeof data.running !== 'boolean' || !('lastRun' in data)
          || !(data.lastRun === null || (typeof data.lastRun === 'object' && !Array.isArray(data.lastRun)))
          || !Array.isArray(data.openFindingsBySeverity) || !Array.isArray(data.proposalsByStatus)) throw new Error();
      return;
    } catch {
      if (attempt === attempts) throw new Error('Worker status could not be verified; check AGENT_TOKEN and run npm run seo:status.');
      // Only read-only verification is retried, to allow a new deployment to
      // become reachable. Resource creation/schema/publication are never retried.
      await new Promise(done => setTimeout(done, attempt * 1_000));
    }
  }
}

export async function deploy({ rootDir = ROOT, env = process.env, fetchImpl = globalThis.fetch,
  wrangler = runWrangler, progress = () => {} } = {}) {
  // This check deliberately precedes every filesystem mutation and API call.
  const { cloudflareToken, agentToken } = requireCredentials(env);
  const config = await readConfig(rootDir);
  const internalLlmsSecrets = await validateInternalLlmsSecrets({ env, siteUrl: config.siteUrl });
  try {
    await access(join(rootDir, 'services/seo-agent/node_modules/wrangler/bin/wrangler.js'));
    await access(join(rootDir, 'services/seo-agent/schema.sql'));
  } catch { throw new Error('Install the vendored Worker dependencies with npm run seo:install before deploying.'); }
  if (env.CLOUDFLARE_ACCOUNT_ID && env.CLOUDFLARE_ACCOUNT_ID !== config.accountId) {
    throw new Error('CLOUDFLARE_ACCOUNT_ID does not match config/seo-agent.json.');
  }
  const client = new CloudflareClient(config.accountId, cloudflareToken, fetchImpl);
  // Confirm the target before creating resources; never register a new account
  // subdomain, start an interactive login, or switch to an ephemeral account.
  const url = await accountWorkerUrl(client, config);
  await configure({ rootDir });
  const childContext = { rootDir, env, accountId: config.accountId };
  progress('Checking the Worker bundle locally.');
  await wrangler(['deploy', '--dry-run'], childContext);
  progress('Looking up or creating the configured D1, KV, and queue resources.');
  const resources = await ensureResources(client, config);
  await configure({ rootDir, resources });
  progress('Initializing the remote D1 schema.');
  await wrangler(['d1', 'execute', 'DB', '--remote', '--file', 'schema.sql'], childContext);
  progress('Publishing the Worker and its configured secrets together.');
  // Wrangler's --secrets-file upload retains remote secret_text/secret_key
  // bindings not listed here. An absent optional pair preserves its current
  // remote value; supplied values are validated and published atomically.
  await withSecretsFile({ AGENT_TOKEN: agentToken, ...internalLlmsSecrets }, filename => wrangler(['deploy', '--secrets-file', filename], childContext));
  progress('Verifying authenticated Worker status.');
  await verifyWorker(url, agentToken, fetchImpl, 3);
  return { url, dashboardUrl: `${url}/dashboard`, siteUrl: config.siteUrl };
}

export async function status({ rootDir = ROOT, env = process.env, fetchImpl = globalThis.fetch } = {}) {
  const { cloudflareToken, agentToken } = requireCredentials(env);
  const config = await readConfig(rootDir);
  if (env.CLOUDFLARE_ACCOUNT_ID && env.CLOUDFLARE_ACCOUNT_ID !== config.accountId) {
    throw new Error('CLOUDFLARE_ACCOUNT_ID does not match config/seo-agent.json.');
  }
  const client = new CloudflareClient(config.accountId, cloudflareToken, fetchImpl);
  const url = await accountWorkerUrl(client, config);
  await client.request(`/workers/scripts/${config.workerName}/settings`);
  await verifyWorker(url, agentToken, fetchImpl);
  return { url, dashboardUrl: `${url}/dashboard`, siteUrl: config.siteUrl };
}

const HELP = `Usage: node scripts/seo-agent.mjs configure|deploy|status

configure  Generate untracked local Wrangler config with placeholder resource IDs.
deploy     Reuse/provision account resources, initialize D1, publish, and verify.
status     Read Cloudflare Worker settings and verify authenticated GET /status.

Deploy/status require Node 24+, CLOUDFLARE_API_TOKEN and a distinct AGENT_TOKEN
from an external secret manager. Never pass tokens as CLI arguments or config.
Optional INTERNAL_LLMS_KEY and INTERNAL_LLMS_CIPHERTEXT must be supplied together;
they are validated locally, stored as Worker secrets, and never used as vars.
Omitting both preserves any existing remote internal-document secrets.
The fixed account, site, and resource names live in config/seo-agent.json.
Cloudflare API: account-scoped GET/POST /d1/database, /storage/kv/namespaces,
/queues; GET /workers/subdomain and /workers/scripts/<name>/settings.
Resource listing is bounded to 20 pages. Mutating operations are never retried.
No site route or injector is installed by this command.\n`;

export async function main(args = process.argv.slice(2)) {
  if (args.length === 0 || (args.length === 1 && ['--help', '-h', 'help'].includes(args[0]))) {
    process.stdout.write(HELP); return;
  }
  if (args.length !== 1 || !['configure', 'deploy', 'status'].includes(args[0])) throw new Error('Expected configure, deploy, or status. Use --help for usage; token arguments are not accepted.');
  const command = args[0];
  if (command === 'configure') {
    const generated = await configure();
    process.stdout.write(`Prepared local placeholder bindings for ${generated.vars.SITE_URL}. Nothing was deployed.\n`);
    return;
  }
  if (Number(process.versions.node.split('.')[0]) < 24) throw new Error('Deploy/status require Node 24+ with --use-env-proxy to preserve session network settings.');
  const result = command === 'deploy' ? await deploy({ progress: message => process.stdout.write(message + '\n') }) : await status();
  process.stdout.write(`${command === 'deploy' ? 'Deployed and verified' : 'Verified'}: ${result.url}\nDashboard: ${result.dashboardUrl}\nManaged site: ${result.siteUrl}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    // All expected errors are ours and exclude raw upstream/child responses.
    // Redact again at the final boundary in case a future error contains a value.
    let message = error instanceof Error ? error.message : 'SEO command failed.';
    for (const value of [process.env.CLOUDFLARE_API_TOKEN, process.env.AGENT_TOKEN, process.env.INTERNAL_LLMS_KEY, process.env.INTERNAL_LLMS_CIPHERTEXT]) {
      if (value) message = message.split(value).join('[REDACTED]');
    }
    process.stderr.write(`SEO: ${message}\n`);
    process.exitCode = 1;
  });
}
