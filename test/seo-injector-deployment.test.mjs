import assert from 'node:assert/strict';
import { test } from 'node:test';
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { runWrangler } from '../scripts/seo-agent.mjs';
import {
  InjectorCloudflareClient, build, buildWranglerConfig, configure, deploy,
  requireCredentials, status, validateDnsRecords, validateRoutes,
} from '../scripts/seo-injector.mjs';

const config = {
  siteUrl: 'https://dunesub.de', siteName: 'DuneSub',
  accountId: 'c01bd8dd02ec6b1dd3a05ea21649d1b8',
  workerName: 'dunesub-seo-agent', databaseName: 'dunesub-seo-agent-db',
  queueName: 'dunesub-seo-agent-drafts', namespaceTitle: 'dunesub-seo-overrides',
};
const zoneId = '6552a81a371b916ebf354a2a0b08f45d';
const namespaceId = 'abcdef0123456789abcdef0123456789';
const env = { CLOUDFLARE_API_TOKEN: 'cloudflare-test-secret' };
const zone = {
  id: zoneId, name: 'dunesub.de', status: 'active', type: 'full',
  account: { id: config.accountId }, name_servers: ['frank.ns.cloudflare.com', 'reza.ns.cloudflare.com'],
};
const records = [
  { name: 'dunesub.de', type: 'A', content: '198.49.23.145', proxied: true },
  { name: 'dunesub.de', type: 'A', content: '198.185.159.145', proxied: true },
  { name: 'dunesub.de', type: 'MX', content: 'mail.example.com', proxied: false },
  { name: 'www.dunesub.de', type: 'CNAME', content: 'ext-sq.squarespace.com.', proxied: true },
  { name: 'verification.dunesub.de', type: 'CNAME', content: 'verify.example.com', proxied: false },
];
const response = (result, status = 200, extra = {}) => new Response(JSON.stringify({ success: status === 200, result, ...extra }), { status });

async function fixture(t, input = config) {
  const rootDir = await mkdtemp(join(tmpdir(), 'ecosystem-injector-test-'));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  await mkdir(join(rootDir, 'config'), { recursive: true });
  await mkdir(join(rootDir, 'services/seo-agent/node_modules/wrangler/bin'), { recursive: true });
  await mkdir(join(rootDir, 'services/seo-injector/src'), { recursive: true });
  await writeFile(join(rootDir, 'config/seo-agent.json'), JSON.stringify(input));
  await writeFile(join(rootDir, 'services/seo-agent/node_modules/wrangler/bin/wrangler.js'), '');
  await writeFile(join(rootDir, 'services/seo-injector/src/index.mjs'), 'export default { fetch: () => new Response("origin") };');
  return rootDir;
}

function mockApi({ zoneResult = zone, dnsRecords = records, dnsStatus = 200, routes = [], bindings,
  zoneList = [zone], settingsStatus = 200 } = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, `Bearer ${env.CLOUDFLARE_API_TOKEN}`);
    assert.ok(options.signal instanceof AbortSignal);
    const request = new URL(url);
    if (request.pathname === '/client/v4/zones') return response(zoneList);
    if (request.pathname === `/client/v4/zones/${zoneId}`) return response(zoneResult);
    if (request.pathname === `/client/v4/zones/${zoneId}/dns_records`) {
      return response(dnsRecords, dnsStatus, dnsStatus === 200 ? {} : { errors: [{ message: env.CLOUDFLARE_API_TOKEN }] });
    }
    if (request.pathname === `/client/v4/zones/${zoneId}/workers/routes`) return response(routes);
    if (request.pathname === `/client/v4/accounts/${config.accountId}/workers/scripts/${config.workerName}/settings`) {
      return response({ bindings: bindings ?? [{ name: 'OVERRIDES', type: 'kv_namespace', namespace_id: namespaceId }] }, settingsStatus);
    }
    assert.fail(`Unexpected mocked API path: ${request.pathname}`);
  };
  return { fetchImpl, calls };
}

const generatedPath = rootDir => join(rootDir, 'services/seo-injector/wrangler.jsonc');

test('configure is local-only and emits private placeholder config with exact native-origin routes', async t => {
  const rootDir = await fixture(t);
  const generated = await configure({ rootDir });
  assert.equal(generated.name, 'dunesub-seo-injector');
  assert.equal(generated.main, './src/index.mjs');
  assert.equal(generated.account_id, config.accountId);
  assert.equal(generated.compatibility_date, '2025-06-17');
  assert.equal(generated.workers_dev, false);
  assert.equal(generated.preview_urls, false);
  assert.deepEqual(generated.observability, { enabled: true });
  assert.deepEqual(generated.kv_namespaces, [{ binding: 'SEO_OVERRIDES', id: '0'.repeat(32) }]);
  assert.deepEqual(generated.routes, [
    { pattern: 'dunesub.de/*', zone_id: '0'.repeat(32) },
    { pattern: 'www.dunesub.de/*', zone_id: '0'.repeat(32) },
  ]);
  const text = await readFile(generatedPath(rootDir), 'utf8');
  assert.match(text, /LOCAL PLACEHOLDERS ONLY/);
  assert.doesNotMatch(text, /AGENT_TOKEN|CLOUDFLARE_API_TOKEN|ORIGIN_HOST|custom_domain/);
  assert.equal((await stat(generatedPath(rootDir))).mode & 0o777, 0o600);
  await writeFile(generatedPath(rootDir), 'old', { mode: 0o644 });
  await configure({ rootDir, resources: { zoneId, namespaceId } });
  assert.equal((await stat(generatedPath(rootDir))).mode & 0o777, 0o600);
});

test('configuration rejects other targets and invalid live resource identifiers', async t => {
  for (const input of [
    { ...config, siteUrl: 'https://other.example' },
    { ...config, accountId: 'a'.repeat(32) },
    { ...config, workerName: 'other-worker' },
    { ...config, AGENT_TOKEN: 'must-not-serialize' },
  ]) {
    const rootDir = await fixture(t, input);
    await assert.rejects(configure({ rootDir }));
    await assert.rejects(access(generatedPath(rootDir)), { code: 'ENOENT' });
  }
  for (const resources of [
    { zoneId: 'invalid', namespaceId }, { zoneId, namespaceId: '0'.repeat(32) }, { zoneId: '0'.repeat(32), namespaceId },
  ]) assert.throws(() => buildWranglerConfig(config, resources), /identifiers/);
});

test('canonical www configuration retains both apex and www route patterns', async t => {
  const rootDir = await fixture(t, { ...config, siteUrl: 'https://www.dunesub.de/' });
  const generated = await configure({ rootDir });
  assert.deepEqual(generated.routes.map(route => route.pattern), ['dunesub.de/*', 'www.dunesub.de/*']);
  const api = mockApi();
  assert.equal((await status({ rootDir, env, fetchImpl: api.fetchImpl })).siteUrl, 'https://www.dunesub.de');
});

test('build checks the local injector using shared private Wrangler execution without credentials', async t => {
  const rootDir = await fixture(t);
  const invocations = [];
  const result = await build({ rootDir, env: { ...env, AGENT_TOKEN: 'unused-control-secret', INTERNAL_LLMS_KEY: 'private-key-fixture', INTERNAL_LLMS_CIPHERTEXT: 'private-envelope-fixture', HTTPS_PROXY: 'http://127.0.0.1:9' }, wrangler: async (args, context) => {
    invocations.push(args);
    assert.equal(context.rootDir, rootDir);
    assert.equal(context.accountId, config.accountId);
    assert.equal(context.env.CLOUDFLARE_API_TOKEN, undefined);
    assert.equal(context.env.AGENT_TOKEN, undefined);
    assert.equal(context.env.INTERNAL_LLMS_KEY, undefined);
    assert.equal(context.env.INTERNAL_LLMS_CIPHERTEXT, undefined);
    assert.equal(context.env.HTTPS_PROXY, 'http://127.0.0.1:9');
    assert.match(await readFile(generatedPath(rootDir), 'utf8'), /LOCAL PLACEHOLDERS ONLY/);
  } });
  assert.deepEqual(invocations, [[
    'deploy', '--dry-run', '--config', resolve(generatedPath(rootDir)),
    '--outdir', join(rootDir, 'services/seo-injector/dist'),
  ]]);
  assert.equal(result.outDir, join(rootDir, 'services/seo-injector/dist'));
});

test('deploy requires only a Cloudflare environment token and rejects account mismatch before requests or writes', async t => {
  const rootDir = await fixture(t);
  let calls = 0;
  const fetchImpl = () => { calls++; throw new Error('should not fetch'); };
  for (const credentials of [{}, { CLOUDFLARE_API_TOKEN: '' }, { CLOUDFLARE_API_TOKEN: 'bad\nsecret' }, { ...env, CLOUDFLARE_ACCOUNT_ID: 'other' }]) {
    await assert.rejects(deploy({ rootDir, env: credentials, fetchImpl, wrangler: () => { calls++; } }));
    await assert.rejects(access(generatedPath(rootDir)), { code: 'ENOENT' });
  }
  assert.equal(calls, 0);
  assert.equal(requireCredentials(env), env.CLOUDFLARE_API_TOKEN);
});

test('pending zone fails before file mutation, DNS access, or Wrangler and reports assigned nameservers', async t => {
  const rootDir = await fixture(t);
  await writeFile(generatedPath(rootDir), 'existing config');
  const { fetchImpl, calls } = mockApi({ zoneResult: { ...zone, status: 'pending' } });
  let wranglerCalls = 0;
  await assert.rejects(deploy({ rootDir, env, fetchImpl, wrangler: () => { wranglerCalls++; } }), error => {
    assert.match(error.message, /pending.*active full zone/);
    assert.match(error.message, /frank\.ns\.cloudflare\.com, reza\.ns\.cloudflare\.com/);
    return true;
  });
  assert.equal(await readFile(generatedPath(rootDir), 'utf8'), 'existing config');
  assert.equal(calls.length, 2);
  assert.equal(wranglerCalls, 0);
});

test('full active zone and the configured account are mandatory before production writes', async t => {
  for (const zoneResult of [
    { ...zone, type: 'partial' }, { ...zone, account: { id: 'a'.repeat(32) } }, { ...zone, name: 'other.example' },
  ]) {
    const rootDir = await fixture(t);
    const api = mockApi({ zoneResult });
    await assert.rejects(deploy({ rootDir, env, fetchImpl: api.fetchImpl, wrangler: () => assert.fail('Wrangler must not run') }));
    await assert.rejects(access(generatedPath(rootDir)), { code: 'ENOENT' });
    assert.equal(api.calls.length, 2);
  }
});

test('DNS HTTP 403 blocks deployment without mutations and never exposes upstream tokens', async t => {
  const rootDir = await fixture(t);
  const api = mockApi({ dnsStatus: 403 });
  await assert.rejects(deploy({ rootDir, env, fetchImpl: api.fetchImpl, wrangler: () => assert.fail('Wrangler must not run') }), error => {
    assert.match(error.message, /HTTP 403/);
    assert.ok(!error.message.includes(env.CLOUDFLARE_API_TOKEN));
    return true;
  });
  assert.equal(api.calls.length, 3);
  await assert.rejects(access(generatedPath(rootDir)), { code: 'ENOENT' });
});

test('status distinguishes pending zone and DNS permission block using only GET and no config writes', async t => {
  const rootDir = await fixture(t);
  const api = mockApi({ zoneResult: { ...zone, status: 'pending' }, dnsStatus: 403 });
  const result = await status({ rootDir, env, fetchImpl: api.fetchImpl });
  assert.equal(result.zone.status, 'pending');
  assert.equal(result.zone.type, 'full');
  assert.deepEqual(result.zone.nameservers, zone.name_servers);
  assert.equal(result.dns.state, 'read-blocked');
  assert.match(result.dns.message, /HTTP 403/);
  assert.equal(result.routes.state, 'verified');
  assert.equal(result.sharedKv.namespaceId, namespaceId);
  assert.equal(result.ready, false);
  assert.ok(api.calls.every(call => call.options.method === 'GET'));
  await assert.rejects(access(generatedPath(rootDir)), { code: 'ENOENT' });
});

test('DNS verification blocks wrong origin, IPv6, www A/AAAA, missing records, and unproxied records', () => {
  const invalidRecords = [
    records.filter(record => record.type !== 'A'),
    records.map(record => record.type === 'A' ? { ...record, content: '203.0.113.8' } : record),
    [...records, { name: 'dunesub.de', type: 'AAAA', content: '2001:db8::1', proxied: true }],
    [...records, { name: 'www.dunesub.de', type: 'A', content: '198.49.23.145', proxied: true }],
    [...records, { name: 'www.dunesub.de', type: 'AAAA', content: '2001:db8::1', proxied: true }],
    records.filter(record => record.name !== 'www.dunesub.de'),
    records.map(record => record.name === 'www.dunesub.de' ? { ...record, content: 'other.squarespace.com' } : record),
    records.map(record => record.type === 'A' ? { ...record, proxied: false } : record),
    records.map(record => record.name === 'www.dunesub.de' ? { ...record, proxied: false } : record),
  ];
  for (const input of invalidRecords) assert.throws(() => validateDnsRecords(input), /Squarespace|proxied/);
  assert.equal(validateDnsRecords(records).state, 'verified');
  for (const address of ['198.49.23.145', '198.185.159.145', '198.49.23.144', '198.185.159.144']) {
    assert.equal(validateDnsRecords([
      { name: 'dunesub.de', type: 'A', content: address, proxied: true }, records[3],
    ]).state, 'verified');
  }
});

test('DNS mismatches and proxy prerequisites fail before config or Wrangler', async t => {
  for (const dnsRecords of [
    records.map(record => record.type === 'A' ? { ...record, content: '203.0.113.1' } : record),
    records.map(record => record.type === 'A' ? { ...record, proxied: false } : record),
  ]) {
    const rootDir = await fixture(t);
    const api = mockApi({ dnsRecords });
    await assert.rejects(deploy({ rootDir, env, fetchImpl: api.fetchImpl, wrangler: () => assert.fail('Wrangler must not run') }));
    await assert.rejects(access(generatedPath(rootDir)), { code: 'ENOENT' });
    assert.equal(api.calls.length, 3);
  }
});

test('conflicting exact site routes block publication while unrelated routes are preserved', async t => {
  const rootDir = await fixture(t);
  const routes = [{ id: 'route', pattern: 'www.dunesub.de/*', script: 'another-worker' }];
  const api = mockApi({ routes });
  await assert.rejects(deploy({ rootDir, env, fetchImpl: api.fetchImpl, wrangler: () => assert.fail('Wrangler must not run') }), /route conflicts/);
  await assert.rejects(access(generatedPath(rootDir)), { code: 'ENOENT' });
  const unrelated = [{ pattern: 'other.example/*', script: 'another-worker' }];
  assert.equal(validateRoutes([...unrelated, { pattern: 'dunesub.de/*', script: 'dunesub-seo-injector' }]).state, 'verified');
  assert.deepEqual(unrelated, [{ pattern: 'other.example/*', script: 'another-worker' }]);
  assert.throws(() => validateRoutes([{ pattern: 'other.example/*', script: 'dunesub-seo-injector' }]), /cannot remove unrelated routes/);
  for (const protocol of ['http', 'https']) {
    for (const hostname of ['dunesub.de', 'www.dunesub.de']) {
      assert.throws(() => validateRoutes([{ pattern: `${protocol}://${hostname}/*`, script: 'other-worker' }]), /route conflicts/);
    }
  }
});

test('live shared KV binding must be unique, correctly typed, and a non-placeholder 32-hex ID', async t => {
  for (const bindings of [
    [], [{ name: 'OVERRIDES', type: 'plain_text', text: 'secret' }],
    [{ name: 'OVERRIDES', type: 'kv_namespace', namespace_id: 'invalid' }],
    [{ name: 'OVERRIDES', type: 'kv_namespace', namespace_id: '0'.repeat(32) }],
    [1, 2].map(() => ({ name: 'OVERRIDES', type: 'kv_namespace', namespace_id: namespaceId })),
  ]) {
    const rootDir = await fixture(t);
    const api = mockApi({ bindings });
    await assert.rejects(deploy({ rootDir, env, fetchImpl: api.fetchImpl, wrangler: () => assert.fail('Wrangler must not run') }), /valid OVERRIDES/);
    await assert.rejects(access(generatedPath(rootDir)), { code: 'ENOENT' });
  }
});

test('successful deploy shares control KV and supplies the absolute injector config to both Wrangler stages', async t => {
  const rootDir = await fixture(t);
  const api = mockApi({ routes: [{ pattern: 'unrelated.example/*', script: 'other-worker' }] });
  const invocations = [];
  const result = await deploy({ rootDir, env: { ...env, AGENT_TOKEN: 'must-not-be-used', INTERNAL_LLMS_KEY: 'private-key-fixture', INTERNAL_LLMS_CIPHERTEXT: 'private-envelope-fixture' }, fetchImpl: api.fetchImpl,
    wrangler: async (args, context) => {
      invocations.push(args);
      assert.equal(context.rootDir, rootDir);
      assert.equal(context.accountId, config.accountId);
      assert.equal(context.env.AGENT_TOKEN, undefined);
    assert.equal(context.env.INTERNAL_LLMS_KEY, undefined);
    assert.equal(context.env.INTERNAL_LLMS_CIPHERTEXT, undefined);
      assert.equal(context.env.CLOUDFLARE_API_TOKEN, env.CLOUDFLARE_API_TOKEN);
      const generated = JSON.parse((await readFile(generatedPath(rootDir), 'utf8')).replace(/^\/\/.*\n/, ''));
      assert.deepEqual(generated.kv_namespaces, [{ binding: 'SEO_OVERRIDES', id: namespaceId }]);
      assert.deepEqual(generated.routes.map(route => route.zone_id), [zoneId, zoneId]);
    },
  });
  assert.deepEqual(invocations, [
    ['deploy', '--dry-run', '--config', resolve(generatedPath(rootDir))],
    ['deploy', '--config', resolve(generatedPath(rootDir))],
  ]);
  assert.equal(result.siteUrl, 'https://dunesub.de');
  const text = await readFile(generatedPath(rootDir), 'utf8');
  assert.ok(!text.includes(env.CLOUDFLARE_API_TOKEN));
  assert.doesNotMatch(text, /must-not-be-used|AGENT_TOKEN|ORIGIN_HOST|custom_domain/);
  assert.equal(api.calls.length, 5);
  assert.ok(api.calls.every(call => call.options.method === 'GET'));
});

test('Wrangler dry-run failure prevents deployment and publication failures are never retried', async t => {
  for (const failingStage of ['dry-run', 'publish']) {
    const rootDir = await fixture(t);
    const api = mockApi();
    const invocations = [];
    await assert.rejects(deploy({ rootDir, env, fetchImpl: api.fetchImpl, wrangler: async args => {
      invocations.push(args);
      if (args.includes('--dry-run') === (failingStage === 'dry-run')) throw new Error('mocked Wrangler failure');
    } }), /mocked Wrangler failure/);
    assert.equal(invocations.length, failingStage === 'dry-run' ? 1 : 2);
  }
});

test('shared Wrangler runner receives the injector config directory and excludes the control secret', async t => {
  const rootDir = await fixture(t);
  const probe = join(rootDir, 'probe.json');
  await writeFile(join(rootDir, 'services/seo-agent/node_modules/wrangler/bin/wrangler.js'), `
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const config = args[args.indexOf('--config') + 1];
const text = fs.readFileSync(config, 'utf8').replace(/^\\/\\/.*\\n/, '');
const generated = JSON.parse(text);
const calls = fs.existsSync(process.env.INJECTOR_TEST_PROBE) ? JSON.parse(fs.readFileSync(process.env.INJECTOR_TEST_PROBE, 'utf8')) : [];
calls.push({ args, config, main: path.resolve(path.dirname(config), generated.main), cwd: process.cwd(), agentPresent: !!process.env.AGENT_TOKEN });
fs.writeFileSync(process.env.INJECTOR_TEST_PROBE, JSON.stringify(calls));
`);
  const api = mockApi();
  await deploy({ rootDir, env: { ...process.env, ...env, AGENT_TOKEN: 'unused-control-secret', INJECTOR_TEST_PROBE: probe }, fetchImpl: api.fetchImpl, wrangler: runWrangler });
  const calls = JSON.parse(await readFile(probe, 'utf8'));
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(call.config, resolve(generatedPath(rootDir)));
    assert.equal(call.main, join(rootDir, 'services/seo-injector/src/index.mjs'));
    assert.equal(call.cwd, join(rootDir, 'services/seo-agent'));
    assert.equal(call.agentPresent, false);
    assert.equal(dirname(call.config), join(rootDir, 'services/seo-injector'));
  }
});

test('zone API rejects oversized, malformed, and transport responses without leaking upstream text or retrying', async () => {
  for (const mode of ['oversized', 'declared', 'malformed', 'transport', 'http']) {
    let requests = 0;
    const client = new InjectorCloudflareClient(config.accountId, env.CLOUDFLARE_API_TOKEN, async () => {
      requests++;
      if (mode === 'transport') throw new Error(env.CLOUDFLARE_API_TOKEN);
      if (mode === 'malformed') return new Response(env.CLOUDFLARE_API_TOKEN);
      if (mode === 'http') return response(null, 403, { errors: [{ message: env.CLOUDFLARE_API_TOKEN }] });
      return new Response(new Uint8Array(1_048_577), { headers: mode === 'declared' ? { 'content-length': '1048577' } : { 'content-length': '1' } });
    });
    await assert.rejects(client.zoneRequest('/zones'), error => {
      assert.ok(!error.message.includes(env.CLOUDFLARE_API_TOKEN));
      return true;
    });
    assert.equal(requests, 1);
    await assert.rejects(client.zoneRequest('//untrusted.example'), /Invalid Cloudflare API path/);
    assert.throws(() => client.request('/workers/scripts/worker/settings', 'POST'), /only GET/);
    assert.equal(requests, 1);
  }
});

test('zone resource pagination honors metadata and rejects unbounded listings', async () => {
  let requests = 0;
  const client = new InjectorCloudflareClient(config.accountId, env.CLOUDFLARE_API_TOKEN, async url => {
    requests++;
    const page = Number(new URL(url).searchParams.get('page'));
    return response([{ id: String(page) }], 200, { result_info: { total_pages: 2 } });
  });
  assert.deepEqual(await client.list('/zones?name=dunesub.de'), [{ id: '1' }, { id: '2' }]);
  assert.equal(requests, 2);
  const endless = new InjectorCloudflareClient(config.accountId, env.CLOUDFLARE_API_TOKEN,
    async () => response(Array.from({ length: 100 }, () => ({}))));
  await assert.rejects(endless.list('/zones'), /20 pages/);
});
