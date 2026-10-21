#!/usr/bin/env node
import { access, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CloudflareClient, runWrangler, validateConfig } from './seo-agent.mjs';
import { INTERNAL_LLMS_SECRET_NAMES } from './internal-llms.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const API = 'https://api.cloudflare.com/client/v4';
const ACCOUNT_ID = 'c01bd8dd02ec6b1dd3a05ea21649d1b8';
const SITE = 'dunesub.de';
const CONTROL_WORKER = 'dunesub-seo-agent';
const INJECTOR = 'dunesub-seo-injector';
const HEX_ID = /^[a-f0-9]{32}$/i;
const PLACEHOLDER_ID = '00000000000000000000000000000000';
const PATTERNS = [`${SITE}/*`, `www.${SITE}/*`];
const SQUARESPACE_IPV4 = new Set(['198.49.23.145', '198.185.159.145', '198.49.23.144', '198.185.159.144']);
const isSiteUrl = value => [`https://${SITE}`, `https://www.${SITE}`].includes(value);

async function readConfig(rootDir) {
  let input;
  try { input = JSON.parse(await readFile(join(rootDir, 'config/seo-agent.json'), 'utf8')); }
  catch { throw new Error('Could not read config/seo-agent.json.'); }
  const config = validateConfig(input);
  if (!isSiteUrl(config.siteUrl) || config.accountId !== ACCOUNT_ID || config.workerName !== CONTROL_WORKER) {
    throw new Error('The injector requires the configured dunesub.de site, Cloudflare account, and control Worker.');
  }
  return config;
}

export function requireCredentials(env) {
  const token = env.CLOUDFLARE_API_TOKEN;
  if (typeof token !== 'string' || !token.trim()) {
    throw new Error('Set CLOUDFLARE_API_TOKEN through your external secret manager before deploying or checking status.');
  }
  if (/\s/.test(token)) throw new Error('CLOUDFLARE_API_TOKEN must not contain whitespace or line breaks.');
  return token;
}

function checkAccount(env, config) {
  if (env.CLOUDFLARE_ACCOUNT_ID && env.CLOUDFLARE_ACCOUNT_ID !== config.accountId) {
    throw new Error('CLOUDFLARE_ACCOUNT_ID does not match config/seo-agent.json.');
  }
}

// Bound both the network operation and streamed body, even with an injected
// fetch that does not honor AbortSignal. Never include upstream error text.
async function requestJson(fetchImpl, base, path, token) {
  if (!/^\/[a-z0-9/_-]+(?:\?[a-z0-9_.=&%+-]+)?$/i.test(path)) throw new Error('Invalid Cloudflare API path.');
  const controller = new AbortController();
  let reader;
  let timeout;
  const expired = new Promise((_, reject) => {
    timeout = setTimeout(() => { controller.abort(); reject(new Error('timeout')); }, 20_000);
  });
  let response;
  let data;
  try {
    response = await Promise.race([fetchImpl(base + path, {
      method: 'GET', headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: controller.signal,
    }), expired]);
    const limit = 1_048_576;
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > limit) throw new Error('oversized');
    reader = response.body?.getReader();
    if (!reader) throw new Error('missing body');
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await Promise.race([reader.read(), expired]);
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error('oversized');
      chunks.push(value);
    }
    data = JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
  } catch {
    throw new Error('Cloudflare GET request failed or returned an unreadable response; no automatic retry was performed.');
  } finally {
    clearTimeout(timeout);
    if (reader) {
      void reader.cancel().catch(() => {});
      try { reader.releaseLock(); } catch { /* A timed-out read can still be pending. */ }
    } else if (response?.body) { void response.body.cancel().catch(() => {}); }
  }
  if (!response.ok || data?.success !== true) {
    const error = new Error(`Cloudflare GET request failed (HTTP ${response.status}); check token read permissions. No automatic retry was performed.`);
    error.status = response.status;
    throw error;
  }
  return data;
}

// Keep the existing account-client contract, adding global zone endpoints and
// the injector's stricter 20-second, read-only request boundary.
export class InjectorCloudflareClient extends CloudflareClient {
  request(path, method = 'GET') {
    if (method !== 'GET') throw new Error('Injector connection checks permit only GET requests.');
    return requestJson(this.fetch, this.base, path, this.token);
  }

  zoneRequest(path) { return requestJson(this.fetch, API, path, this.token); }

  async list(path) {
    const entries = [];
    for (let page = 1; page <= 20; page++) {
      const data = await this.zoneRequest(`${path}${path.includes('?') ? '&' : '?'}page=${page}&per_page=100`);
      if (!Array.isArray(data.result)) throw new Error('Cloudflare returned an invalid zone resource list.');
      entries.push(...data.result);
      const info = data.result_info;
      const totalPages = Number.isInteger(info?.total_pages) && info.total_pages >= 0 ? info.total_pages : null;
      const totalCount = Number.isInteger(info?.total_count) && info.total_count >= 0 ? info.total_count : null;
      if (totalPages !== null ? page >= totalPages : totalCount !== null ? entries.length >= totalCount : data.result.length < 100) return entries;
    }
    throw new Error('Cloudflare zone resource lookup exceeded 20 pages.');
  }
}

export async function findZone(client, config) {
  const zones = (await client.list(`/zones?name=${SITE}`)).filter(zone => zone?.name === SITE);
  if (zones.length !== 1 || !HEX_ID.test(zones[0]?.id ?? '') || zones[0].id === PLACEHOLDER_ID) {
    throw new Error('Exactly one valid Cloudflare zone for dunesub.de is required.');
  }
  const zone = (await client.zoneRequest(`/zones/${zones[0].id}`)).result;
  if (!zone || zone.id !== zones[0].id || zone.name !== SITE || zone.account?.id !== config.accountId) {
    throw new Error('The Cloudflare zone does not match the configured site and account.');
  }
  const nameservers = Array.isArray(zone.name_servers) ? zone.name_servers.filter(value =>
    typeof value === 'string' && /^[a-z0-9-]+\.ns\.cloudflare\.com$/.test(value)) : [];
  return {
    id: zone.id, name: SITE, accountId: config.accountId,
    status: ['initializing', 'pending', 'active', 'moved', 'deactivated'].includes(zone.status) ? zone.status : 'unknown',
    type: ['full', 'partial', 'secondary'].includes(zone.type) ? zone.type : 'unknown',
    nameservers,
  };
}

export function validateDeploymentZone(zone) {
  if (zone.status !== 'active' || zone.type !== 'full') {
    throw new Error(`Cloudflare zone dunesub.de is ${zone.status}; production deployment requires an active full zone. Assigned nameservers: ${zone.nameservers.join(', ') || 'unavailable'}.`);
  }
}

export function validateDnsRecords(records) {
  if (!Array.isArray(records)) throw new Error('Cloudflare returned an invalid DNS record list.');
  const named = name => records.filter(record => typeof record?.name === 'string' && record.name.toLowerCase().replace(/\.$/, '') === name);
  const apex = named(SITE);
  const www = named(`www.${SITE}`);
  const apexA = apex.filter(record => record.type === 'A');
  if (!apexA.length || apexA.some(record => !SQUARESPACE_IPV4.has(record.content)) || apex.some(record => ['AAAA', 'CNAME'].includes(record.type))) {
    throw new Error('Apex DNS must contain only the expected Squarespace A records and no AAAA or CNAME records.');
  }
  const wwwCname = www.filter(record => record.type === 'CNAME');
  if (wwwCname.length !== 1 || typeof wwwCname[0].content !== 'string'
      || wwwCname[0].content.toLowerCase().replace(/\.$/, '') !== 'ext-sq.squarespace.com'
      || www.some(record => ['A', 'AAAA'].includes(record.type))) {
    throw new Error('www DNS must use the Squarespace CNAME ext-sq.squarespace.com with no A or AAAA records.');
  }
  if ([...apexA, ...wwwCname].some(record => record.proxied !== true)) {
    throw new Error('All expected Squarespace apex A and www CNAME records must already be proxied before deployment.');
  }
  return { state: 'verified', apexARecords: apexA.length, wwwCname: 'ext-sq.squarespace.com', proxied: true };
}

export function validateRoutes(routes) {
  if (!Array.isArray(routes)) throw new Error('Cloudflare returned an invalid Worker route list.');
  if (routes.some(route => route?.script === INJECTOR && !PATTERNS.includes(route.pattern))) {
    throw new Error('The injector already owns an additional route; resolve it before deployment so Wrangler cannot remove unrelated routes.');
  }
  for (const pattern of PATTERNS) {
    const matches = routes.filter(route => typeof route?.pattern === 'string'
      && route.pattern.replace(/^https?:\/\//i, '') === pattern);
    if (matches.length > 1 || matches.some(route => route.script != null && route.script !== INJECTOR)) {
      throw new Error(`The ${pattern} route conflicts with another Worker or an ambiguous route. Resolve it before deployment.`);
    }
  }
  return { state: 'verified', patterns: [...PATTERNS] };
}

export async function sharedNamespace(client, config) {
  const settings = (await client.request(`/workers/scripts/${config.workerName}/settings`)).result;
  const bindings = Array.isArray(settings?.bindings) ? settings.bindings.filter(binding => binding?.name === 'OVERRIDES') : [];
  if (bindings.length !== 1 || bindings[0].type !== 'kv_namespace' || !HEX_ID.test(bindings[0].namespace_id ?? '') || bindings[0].namespace_id === PLACEHOLDER_ID) {
    throw new Error('The live control Worker must expose one valid OVERRIDES KV namespace binding.');
  }
  return bindings[0].namespace_id;
}

export function buildWranglerConfig(config, resources) {
  if (!isSiteUrl(config?.siteUrl) || config?.accountId !== ACCOUNT_ID || config?.workerName !== CONTROL_WORKER) {
    throw new Error('The injector requires the configured dunesub.de site, Cloudflare account, and control Worker.');
  }
  if (resources && (!HEX_ID.test(resources.zoneId ?? '') || !HEX_ID.test(resources.namespaceId ?? '')
      || resources.zoneId === PLACEHOLDER_ID || resources.namespaceId === PLACEHOLDER_ID)) {
    throw new Error('Valid live Cloudflare zone and KV identifiers are required.');
  }
  return {
    $schema: '../seo-agent/node_modules/wrangler/config-schema.json',
    name: INJECTOR, account_id: config.accountId, main: './src/index.mjs',
    compatibility_date: '2025-06-17', workers_dev: false, preview_urls: false,
    observability: { enabled: true },
    kv_namespaces: [{ binding: 'SEO_OVERRIDES', id: resources?.namespaceId ?? PLACEHOLDER_ID }],
    routes: PATTERNS.map(pattern => ({ pattern, zone_id: resources?.zoneId ?? PLACEHOLDER_ID })),
  };
}

export async function configure({ rootDir = ROOT, resources } = {}) {
  const generated = buildWranglerConfig(await readConfig(rootDir), resources);
  const target = join(rootDir, 'services/seo-injector/wrangler.jsonc');
  const notice = resources ? '// Generated deployment bindings; identifiers are intentionally untracked.\n'
    : '// LOCAL PLACEHOLDERS ONLY. Use seo:injector:deploy after the zone and proxied Squarespace DNS are ready.\n';
  try {
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, notice + JSON.stringify(generated, null, 2) + '\n', { mode: 0o600 });
    await chmod(target, 0o600);
  } catch { throw new Error('Could not write the generated injector configuration.'); }
  return generated;
}

async function checkDependencies(rootDir) {
  try {
    await access(join(rootDir, 'services/seo-agent/node_modules/wrangler/bin/wrangler.js'));
    await access(join(rootDir, 'services/seo-injector/src/index.mjs'));
  } catch { throw new Error('Install the shared Wrangler dependencies with npm run seo:install and provide the injector source before building or deploying.'); }
}

export async function build({ rootDir = ROOT, env = process.env, wrangler = runWrangler } = {}) {
  const config = await readConfig(rootDir);
  await checkDependencies(rootDir);
  await configure({ rootDir });
  const childEnv = { ...env };
  delete childEnv.AGENT_TOKEN;
  for (const name of INTERNAL_LLMS_SECRET_NAMES) delete childEnv[name];
  delete childEnv.CLOUDFLARE_API_TOKEN;
  const configPath = resolve(rootDir, 'services/seo-injector/wrangler.jsonc');
  const outDir = resolve(rootDir, 'services/seo-injector/dist');
  await wrangler(['deploy', '--dry-run', '--config', configPath, '--outdir', outDir], {
    rootDir, env: childEnv, accountId: config.accountId,
  });
  return { siteUrl: config.siteUrl, outDir };
}

async function checkedRead(action) {
  try { return await action(); }
  catch (error) {
    if ([401, 403].includes(error?.status)) return { state: 'read-blocked', message: error.message };
    throw error;
  }
}

function checkedValidation(action) {
  try { return action(); }
  catch (error) { return { state: 'mismatch', message: error.message }; }
}

export async function status({ rootDir = ROOT, env = process.env, fetchImpl = globalThis.fetch } = {}) {
  const token = requireCredentials(env);
  const config = await readConfig(rootDir);
  checkAccount(env, config);
  const client = new InjectorCloudflareClient(config.accountId, token, fetchImpl);
  const zone = await findZone(client, config);
  const dns = await checkedRead(async () => {
    const records = await client.list(`/zones/${zone.id}/dns_records`);
    return checkedValidation(() => validateDnsRecords(records));
  });
  const routes = await checkedRead(async () => {
    const existing = await client.list(`/zones/${zone.id}/workers/routes`);
    return checkedValidation(() => validateRoutes(existing));
  });
  const sharedKv = await checkedRead(async () => ({ state: 'verified', namespaceId: await sharedNamespace(client, config) }));
  return {
    siteUrl: config.siteUrl, workerName: INJECTOR, zone, dns, routes, sharedKv,
    ready: zone.status === 'active' && zone.type === 'full'
      && [dns, routes, sharedKv].every(check => check.state === 'verified'),
  };
}

export async function deploy({ rootDir = ROOT, env = process.env, fetchImpl = globalThis.fetch,
  wrangler = runWrangler, progress = () => {} } = {}) {
  const token = requireCredentials(env);
  const config = await readConfig(rootDir);
  checkAccount(env, config);
  const client = new InjectorCloudflareClient(config.accountId, token, fetchImpl);
  const zone = await findZone(client, config);
  validateDeploymentZone(zone);
  const dns = validateDnsRecords(await client.list(`/zones/${zone.id}/dns_records`));
  validateRoutes(await client.list(`/zones/${zone.id}/workers/routes`));
  const namespaceId = await sharedNamespace(client, config);
  await checkDependencies(rootDir);
  // No file writes or Wrangler invocations occur until every production gate
  // passes. Only Wrangler publication writes routes; DNS remains untouched.
  await configure({ rootDir, resources: { zoneId: zone.id, namespaceId } });
  const configPath = resolve(rootDir, 'services/seo-injector/wrangler.jsonc');
  const childEnv = { ...env };
  delete childEnv.AGENT_TOKEN;
  for (const name of INTERNAL_LLMS_SECRET_NAMES) delete childEnv[name];
  const context = { rootDir, env: childEnv, accountId: config.accountId };
  progress('Checking the injector bundle locally.');
  await wrangler(['deploy', '--dry-run', '--config', configPath], context);
  progress('Publishing the injector on the two verified site routes.');
  await wrangler(['deploy', '--config', configPath], context);
  return { siteUrl: config.siteUrl, workerName: INJECTOR, zone, dns, patterns: [...PATTERNS] };
}

const HELP = `Usage: node scripts/seo-injector.mjs configure|build|status|deploy

configure  Generate untracked local config with placeholder IDs; no credentials needed.
build      Generate placeholder config and check the local bundle without credentials.
status     Read zone, DNS, site routes, and the control Worker's shared KV binding.
deploy     Validate production prerequisites, check the bundle, and publish exact site routes.

Status/deploy require Node 24+ and CLOUDFLARE_API_TOKEN from the environment.
The injector uses native fetch(request) to reach the existing Squarespace DNS origin.
Deployment requires an active full zone in the configured account, DNS read access,
expected Squarespace records already proxied, and no conflicting exact site routes.
This command never activates a zone, changes nameservers, or edits DNS records.
API reads are limited to 1 MiB, 20 seconds, and 20 pages. No mutation is retried.
`;

export async function main(args = process.argv.slice(2)) {
  if (!args.length || (args.length === 1 && ['--help', '-h', 'help'].includes(args[0]))) {
    process.stdout.write(HELP); return;
  }
  if (args.length !== 1 || !['configure', 'build', 'status', 'deploy'].includes(args[0])) {
    throw new Error('Expected configure, build, status, or deploy. Token arguments are not accepted.');
  }
  if (args[0] === 'configure') {
    await configure();
    process.stdout.write('Prepared local injector placeholder bindings for https://dunesub.de. Nothing was deployed.\n');
    return;
  }
  if (args[0] === 'build') {
    const result = await build();
    process.stdout.write(`Checked the injector bundle locally for ${result.siteUrl}. Nothing was deployed.\n`);
    return;
  }
  if (Number(process.versions.node.split('.')[0]) < 24) throw new Error('Status/deploy require Node 24+ with --use-env-proxy to preserve session network settings.');
  const result = args[0] === 'deploy' ? await deploy({ progress: message => process.stdout.write(message + '\n') }) : await status();
  process.stdout.write(`Zone: ${result.zone.status} (${result.zone.type})\nAssigned nameservers: ${result.zone.nameservers.join(', ') || 'unavailable'}\nDNS: ${result.dns.state}\n`);
  if (result.dns.message) process.stdout.write(`DNS check: ${result.dns.message}\n`);
  if (args[0] === 'status') process.stdout.write(`Routes: ${result.routes.state}\nShared KV: ${result.sharedKv.state}\nReady to deploy: ${result.ready ? 'yes' : 'no'}\n`);
  if (args[0] === 'deploy') process.stdout.write('Published dunesub-seo-injector for https://dunesub.de and https://www.dunesub.de.\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    let message = typeof error?.message === 'string' ? error.message : 'Operation failed.';
    for (const token of [process.env.CLOUDFLARE_API_TOKEN, process.env.AGENT_TOKEN, ...INTERNAL_LLMS_SECRET_NAMES.map(name => process.env[name])]) {
      if (token) message = message.replaceAll(token, '[redacted]');
    }
    process.stderr.write(`SEO injector: ${message}\n`);
    process.exitCode = 1;
  });
}
