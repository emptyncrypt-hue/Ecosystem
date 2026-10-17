import assert from 'node:assert/strict';
import { test } from 'node:test';
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import {
  CloudflareClient, buildWranglerConfig, configure, deploy, ensureResources,
  requireCredentials, runWrangler, status, validateConfig, withSecretsFile,
} from '../scripts/seo-agent.mjs';

const config = {
  siteUrl: 'https://dunesub.de', siteName: 'DuneSub',
  accountId: 'c01bd8dd02ec6b1dd3a05ea21649d1b8',
  workerName: 'dunesub-seo-agent', databaseName: 'dunesub-seo-agent-db',
  queueName: 'dunesub-seo-agent-drafts', namespaceTitle: 'dunesub-seo-overrides',
};
const credentials = { CLOUDFLARE_API_TOKEN: 'test-cloudflare-credential', AGENT_TOKEN: 'test-distinct-agent-credential' };
const database = { name: config.databaseName, uuid: '12345678-1234-1234-1234-1234567890ab' };
const namespace = { title: config.namespaceTitle, id: 'abcdef0123456789abcdef0123456789' };
const queue = { queue_name: config.queueName, queue_id: 'fedcba9876543210fedcba9876543210' };
const workerStatus = { lastRun: null, running: false, openFindingsBySeverity: [], proposalsByStatus: [] };
const response = (result, code = 200) => new Response(JSON.stringify({ success: code === 200, result }), { status: code });

async function fixture(t, input = config) {
  const rootDir = await mkdtemp(join(tmpdir(), 'ecosystem-seo-test-'));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  await mkdir(join(rootDir, 'config'), { recursive: true });
  await mkdir(join(rootDir, 'services/seo-agent/node_modules/wrangler/bin'), { recursive: true });
  await writeFile(join(rootDir, 'config/seo-agent.json'), JSON.stringify(input));
  await writeFile(join(rootDir, 'services/seo-agent/schema.sql'), 'CREATE TABLE IF NOT EXISTS example (id INTEGER);');
  await writeFile(join(rootDir, 'services/seo-agent/node_modules/wrangler/bin/wrangler.js'), '');
  return rootDir;
}

function mockApi({ absent = false, failPost = false, badStatus = false } = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    const path = new URL(url).pathname;
    if (path.endsWith('/status')) {
      assert.equal(options.headers.Authorization, `Bearer ${credentials.AGENT_TOKEN}`);
      return new Response(JSON.stringify(badStatus ? { error: 'not a Worker status' } : workerStatus));
    }
    assert.equal(options.headers.Authorization, `Bearer ${credentials.CLOUDFLARE_API_TOKEN}`);
    assert.equal(options.redirect, 'error');
    if (path.endsWith('/workers/subdomain')) return response({ subdomain: 'dunesub-test' });
    if (path.endsWith('/settings')) return response({ bindings: [] });
    const resource = path.endsWith('/d1/database') ? database : path.endsWith('/kv/namespaces') ? namespace : path.endsWith('/queues') ? queue : null;
    assert.ok(resource, `Unexpected request: ${path}`);
    if (options.method === 'POST') {
      if (failPost) return new Response(JSON.stringify({ success: false, errors: [{ message: credentials.CLOUDFLARE_API_TOKEN }] }), { status: 403 });
      return response(resource);
    }
    return response(absent || Number(new URL(url).searchParams.get('page')) > 1 ? [] : [resource]);
  };
  return { calls, fetchImpl };
}

test('SEO deployment configuration targets dunesub and preserves approval policy without credentials', async t => {
  const rootDir = await fixture(t);
  const generated = await configure({ rootDir });
  assert.equal(generated.account_id, config.accountId);
  assert.equal(generated.vars.SITE_URL, 'https://dunesub.de');
  assert.equal(generated.vars.AUTO_APPLY_FIELDS, '');
  assert.equal(generated.workers_dev, true);
  assert.deepEqual(generated.triggers.crons, ['17 6 * * *']);
  assert.equal(generated.queues.producers[0].queue, config.queueName);
  assert.equal(generated.d1_databases[0].binding, 'DB');
  assert.equal(generated.kv_namespaces[0].binding, 'OVERRIDES');
  assert.equal(generated.ai.binding, 'AI');
  const text = await readFile(join(rootDir, 'services/seo-agent/wrangler.jsonc'), 'utf8');
  assert.match(text, /LOCAL PLACEHOLDERS ONLY/);
  assert.doesNotMatch(text, /AGENT_TOKEN|CLOUDFLARE_API_TOKEN/);
});

test('configuration rejects secret fields, account emails, URL credentials, and unsafe resource names', () => {
  for (const invalid of [
    { ...config, AGENT_TOKEN: credentials.AGENT_TOKEN },
    { ...config, accountId: 'plamen.r.mihaylov@gmail.com' },
    { ...config, accountId: [config.accountId] },
    { ...config, siteUrl: 'https://user:password@dunesub.de' },
    { ...config, siteUrl: 'https://dunesub.de/private' },
    { ...config, siteUrl: 'http://dunesub.de' },
    { ...config, workerName: '../other-worker' },
  ]) assert.throws(() => validateConfig(invalid));
  assert.equal(validateConfig({ ...config, siteUrl: 'https://dunesub.de/' }).siteUrl, 'https://dunesub.de');
  assert.throws(() => buildWranglerConfig(config, { databaseId: '00000000-0000-0000-0000-000000000000', namespaceId: namespace.id }), /invalid resource/);
});

test('deployment missing or reused credentials causes no API call or generated-file mutation', async t => {
  const rootDir = await fixture(t);
  const target = join(rootDir, 'services/seo-agent/wrangler.jsonc');
  let calls = 0;
  for (const env of [{}, { CLOUDFLARE_API_TOKEN: 'one' }, { CLOUDFLARE_API_TOKEN: 'same', AGENT_TOKEN: 'same' }]) {
    await assert.rejects(deploy({ rootDir, env, fetchImpl: () => { calls++; }, wrangler: () => { calls++; } }));
    await assert.rejects(access(target), { code: 'ENOENT' });
  }
  assert.equal(calls, 0);
  assert.throws(() => requireCredentials({ CLOUDFLARE_API_TOKEN: 'one\n', AGENT_TOKEN: 'two' }), /line breaks/);
});

test('account mismatch and unavailable dependencies fail before remote requests', async t => {
  const rootDir = await fixture(t);
  let calls = 0;
  await assert.rejects(deploy({ rootDir, env: { ...credentials, CLOUDFLARE_ACCOUNT_ID: 'other' }, fetchImpl: () => { calls++; } }), /does not match/);
  await rm(join(rootDir, 'services/seo-agent/node_modules'), { recursive: true });
  await assert.rejects(deploy({ rootDir, env: credentials, fetchImpl: () => { calls++; } }), /seo:install/);
  assert.equal(calls, 0);
});

test('resource provisioning reuses existing exact-name resources without POST', async () => {
  const { fetchImpl, calls } = mockApi();
  const resources = await ensureResources(new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, fetchImpl), config);
  assert.deepEqual(resources, { databaseId: database.uuid, namespaceId: namespace.id });
  assert.equal(calls.length, 6);
  assert.ok(calls.every(call => call.options.method === 'GET'));
});

test('resource provisioning creates each missing resource once and sends only configured names', async () => {
  const { fetchImpl, calls } = mockApi({ absent: true });
  await ensureResources(new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, fetchImpl), config);
  const posts = calls.filter(call => call.options.method === 'POST');
  assert.equal(posts.length, 3);
  assert.deepEqual(posts.map(call => JSON.parse(call.options.body)), [
    { name: config.databaseName }, { title: config.namespaceTitle }, { queue_name: config.queueName },
  ]);
});

test('failed resource mutation is not retried and response text never leaks tokens', async () => {
  const { fetchImpl, calls } = mockApi({ absent: true, failPost: true });
  await assert.rejects(ensureResources(new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, fetchImpl), config), error => {
    assert.match(error.message, /HTTP 403/);
    assert.ok(!error.message.includes(credentials.CLOUDFLARE_API_TOKEN));
    return true;
  });
  assert.equal(calls.filter(call => call.options.method === 'POST').length, 1);
  assert.equal(calls.length, 2);
});

test('resource pagination is bounded and duplicate names are rejected', async () => {
  let requests = 0;
  const client = new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, async () => {
    requests++;
    return response(Array.from({ length: 100 }, (_, i) => ({ name: `other-${i}` })));
  });
  await assert.rejects(client.find('/d1/database', 'name', config.databaseName), /20 pages/);
  assert.equal(requests, 20);
  const duplicate = new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, async () => response([database, database]));
  await assert.rejects(duplicate.find('/d1/database', 'name', config.databaseName), /Multiple/);
});

test('transport failures and invalid API responses are sanitized without retry', async () => {
  let calls = 0;
  const client = new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, async () => {
    calls++;
    throw new Error(credentials.CLOUDFLARE_API_TOKEN);
  });
  await assert.rejects(client.request('/queues', 'POST', { queue_name: config.queueName }), error => !error.message.includes(credentials.CLOUDFLARE_API_TOKEN));
  assert.equal(calls, 1);
  const bad = new CloudflareClient(config.accountId, 'test', async () => new Response('not json'));
  await assert.rejects(bad.request('/queues'), /unreadable/);
  await assert.rejects(bad.request('//untrusted.example'), /Invalid Cloudflare API path/);
});

test('private temporary secret files have restrictive permissions and are cleaned after success or failure', async () => {
  for (const fail of [false, true]) {
    let path;
    const work = withSecretsFile({ AGENT_TOKEN: credentials.AGENT_TOKEN }, async filename => {
      path = filename;
      assert.deepEqual(JSON.parse(await readFile(filename, 'utf8')), { AGENT_TOKEN: credentials.AGENT_TOKEN });
      assert.equal((await stat(filename)).mode & 0o777, 0o600);
      assert.equal((await stat(dirname(filename))).mode & 0o777, 0o700);
      if (fail) throw new Error('simulated publish failure');
      return 'complete';
    });
    if (fail) await assert.rejects(work, /simulated/); else assert.equal(await work, 'complete');
    await assert.rejects(access(dirname(path)), { code: 'ENOENT' });
  }
});

test('deployment orders schema before publish, passes a private secret file, and verifies real bindings', async t => {
  const rootDir = await fixture(t);
  const { fetchImpl, calls } = mockApi();
  const invocations = [];
  let secretFile;
  const result = await deploy({ rootDir, env: credentials, fetchImpl, wrangler: async (args, context) => {
    invocations.push(args);
    assert.equal(context.accountId, config.accountId);
    assert.ok(!args.includes(credentials.CLOUDFLARE_API_TOKEN));
    assert.ok(!args.includes(credentials.AGENT_TOKEN));
    if (args.includes('--secrets-file')) {
      secretFile = args[args.indexOf('--secrets-file') + 1];
      assert.deepEqual(JSON.parse(await readFile(secretFile, 'utf8')), { AGENT_TOKEN: credentials.AGENT_TOKEN });
    }
  } });
  assert.deepEqual(invocations[0], ['deploy', '--dry-run']);
  assert.deepEqual(invocations[1], ['d1', 'execute', 'DB', '--remote', '--file', 'schema.sql']);
  assert.deepEqual(invocations[2], ['deploy', '--secrets-file', secretFile]);
  assert.equal(result.url, 'https://dunesub-seo-agent.dunesub-test.workers.dev');
  await assert.rejects(access(secretFile), { code: 'ENOENT' });
  assert.ok(calls.at(-1).url.endsWith('/status'));
  const generated = await readFile(join(rootDir, 'services/seo-agent/wrangler.jsonc'), 'utf8');
  assert.ok(generated.includes(database.uuid));
  assert.ok(generated.includes(namespace.id));
  assert.ok(!generated.includes(credentials.AGENT_TOKEN));
});

test('schema failure prevents publishing; publish failure removes the secret file without retry', async t => {
  const rootDir = await fixture(t);
  for (const failAt of ['schema', 'publish']) {
    let publishes = 0;
    let secretFile;
    const { fetchImpl } = mockApi();
    await assert.rejects(deploy({ rootDir, env: credentials, fetchImpl, wrangler: async args => {
      if (args[0] === 'd1' && failAt === 'schema') throw new Error('simulated schema failure');
      if (args.includes('--secrets-file')) {
        publishes++;
        secretFile = args.at(-1);
        throw new Error('simulated publish failure');
      }
    } }), /simulated/);
    assert.equal(publishes, failAt === 'schema' ? 0 : 1);
    if (secretFile) await assert.rejects(access(secretFile), { code: 'ENOENT' });
  }
});

test('local bundle failure prevents resource creation and schema writes', async t => {
  const rootDir = await fixture(t);
  const { fetchImpl, calls } = mockApi({ absent: true });
  await assert.rejects(deploy({ rootDir, env: credentials, fetchImpl, wrangler: async () => { throw new Error('bundle failure'); } }), /bundle failure/);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.endsWith('/workers/subdomain'));
});

test('read-only status checks both Cloudflare and authenticated /status without mutations', async t => {
  const rootDir = await fixture(t);
  const { fetchImpl, calls } = mockApi();
  const result = await status({ rootDir, env: credentials, fetchImpl });
  assert.equal(result.siteUrl, 'https://dunesub.de');
  assert.equal(calls.length, 3);
  assert.ok(calls.every(call => !call.options.method || call.options.method === 'GET'));
  await assert.rejects(access(join(rootDir, 'services/seo-agent/wrangler.jsonc')), { code: 'ENOENT' });
  const bad = mockApi({ badStatus: true });
  await assert.rejects(status({ rootDir, env: credentials, fetchImpl: bad.fetchImpl }), /could not be verified/);
});

test('Wrangler children inherit proxy and CA settings, omit AGENT_TOKEN, and suppress credential output', {
  skip: Number(process.versions.node.split('.')[0]) < 24 ? 'Worker deployment and proxy-aware child execution require Node 24+.' : false,
}, async t => {
  const rootDir = await fixture(t);
  const probe = join(rootDir, 'probe.json');
  const binary = join(rootDir, 'services/seo-agent/node_modules/wrangler/bin/wrangler.js');
  await writeFile(binary, `const fs = require('node:fs');\nfs.writeFileSync(process.env.SEO_TEST_PROBE, JSON.stringify({proxy: process.env.HTTPS_PROXY, ca: process.env.SSL_CERT_FILE, agent: process.env.AGENT_TOKEN, cf: !!process.env.CLOUDFLARE_API_TOKEN, log: process.env.WRANGLER_LOG_PATH, config: process.env.XDG_CONFIG_HOME, cache: process.env.XDG_CACHE_HOME, configMode: fs.statSync(process.env.XDG_CONFIG_HOME + '/.wrangler').mode & 511, cacheMode: fs.statSync(process.env.XDG_CACHE_HOME + '/.wrangler').mode & 511, args: process.argv.slice(2)}));\nconsole.error(process.env.CLOUDFLARE_API_TOKEN);\nprocess.exit(process.env.SEO_TEST_FAIL ? 1 : 0);\n`);
  const env = { ...process.env, ...credentials, SEO_TEST_PROBE: probe, HTTPS_PROXY: 'http://127.0.0.1:9', SSL_CERT_FILE: '/test/session-ca.pem' };
  await runWrangler(['deploy', '--dry-run'], { rootDir, env, accountId: config.accountId });
  const recorded = JSON.parse(await readFile(probe, 'utf8'));
  assert.equal(recorded.proxy, env.HTTPS_PROXY);
  assert.equal(recorded.ca, env.SSL_CERT_FILE);
  assert.equal(recorded.agent, undefined);
  assert.equal(recorded.cf, true);
  assert.equal(recorded.configMode, 0o700);
  assert.equal(recorded.cacheMode, 0o700);
  assert.equal(dirname(recorded.config), dirname(recorded.log));
  assert.equal(dirname(recorded.cache), dirname(recorded.log));
  assert.deepEqual(recorded.args, ['deploy', '--dry-run']);
  await assert.rejects(access(dirname(recorded.log)), { code: 'ENOENT' });
  await assert.rejects(access(recorded.config), { code: 'ENOENT' });
  await assert.rejects(access(recorded.cache), { code: 'ENOENT' });
  await assert.rejects(runWrangler(['deploy'], { rootDir, env: { ...env, SEO_TEST_FAIL: '1' }, accountId: config.accountId }), error => {
    assert.match(error.message, /withheld to protect credentials/);
    assert.ok(!error.message.includes(credentials.CLOUDFLARE_API_TOKEN));
    return true;
  });
});


test('Cloudflare rejects oversized bodies without trusting Content-Length', async () => {
  for (const headers of [{}, { 'content-length': '10' }]) {
    let sent = false;
    let cancelled = false;
    const body = new ReadableStream({
      pull(controller) {
        if (!sent) { controller.enqueue(new Uint8Array(1_048_577)); sent = true; }
      },
      cancel() { cancelled = true; },
    });
    const client = new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, async () => new Response(body, { headers }));
    await assert.rejects(client.request('/queues'), /unreadable response/);
    assert.equal(cancelled, true);
  }
});


test('short Cloudflare pages honor total_pages and reuse resources found later without POST', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    assert.equal(options.method, 'GET');
    const request = new URL(url);
    const page = Number(request.searchParams.get('page'));
    const resource = request.pathname.endsWith('/d1/database') ? database
      : request.pathname.endsWith('/kv/namespaces') ? namespace : queue;
    const first = request.pathname.endsWith('/d1/database') ? { name: 'another-db' }
      : request.pathname.endsWith('/kv/namespaces') ? { title: 'another-title' } : { queue_name: 'another-queue' };
    return new Response(JSON.stringify({ success: true, result: page === 1 ? [first] : [resource],
      result_info: { page, count: 1, per_page: 1, total_count: 2, total_pages: 2 } }));
  };
  const resources = await ensureResources(new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, fetchImpl), config);
  assert.deepEqual(resources, { databaseId: database.uuid, namespaceId: namespace.id });
  assert.equal(calls.length, 6);
  assert.ok(calls.every(call => call.options.method === 'GET'));
});

test('Cloudflare duplicate KV titles across pages are rejected instead of selecting the first', async () => {
  const client = new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, async url => {
    const page = Number(new URL(url).searchParams.get('page'));
    return new Response(JSON.stringify({ success: true, result: [{ ...namespace, id: page === 1 ? namespace.id : 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }],
      result_info: { page, count: 1, per_page: 1, total_count: 2, total_pages: 2 } }));
  });
  await assert.rejects(client.find('/storage/kv/namespaces', 'title', config.namespaceTitle), /Multiple Cloudflare resources/);
});

test('Cloudflare total_count controls pagination when total_pages is absent', async () => {
  let calls = 0;
  const client = new CloudflareClient(config.accountId, credentials.CLOUDFLARE_API_TOKEN, async url => {
    calls++;
    const page = Number(new URL(url).searchParams.get('page'));
    return new Response(JSON.stringify({ success: true, result: page === 1 ? [{ name: 'another-db' }] : [database],
      result_info: { page, count: 1, per_page: 1, total_count: 2 } }));
  });
  assert.deepEqual(await client.find('/d1/database', 'name', config.databaseName), database);
  assert.equal(calls, 2);
});
