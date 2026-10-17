import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runCli } from '../src/seo-agent.mjs';

const TOKEN = 'seo-integration-fixture';
const ENV = { SEO_AGENT_URL: 'https://seo.example.com', SEO_AGENT_TOKEN: TOKEN };
const STATUS = { running: false, lastRun: null, openFindingsBySeverity: [], proposalsByStatus: [] };

async function invoke(args, { env = ENV, cwd, body = STATUS, status = 200, fetchImpl } = {}) {
  let stdout = '';
  let stderr = '';
  const calls = [];
  const code = await runCli(args, {
    env, cwd,
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
    fetchImpl: fetchImpl ?? (async (url, options) => {
      calls.push({ url: String(url), options });
      return Response.json(body, { status });
    }),
  });
  return { code, stdout, stderr, calls };
}

async function configFixture(t, config) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ecosystem-seo-cli-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(path.join(directory, 'seo.json'), JSON.stringify(config));
  return directory;
}

test('SEO CLI defaults to a read-only authenticated status request', async () => {
  const result = await invoke([]);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), STATUS);
  assert.equal(result.calls.length, 1);
  assert.equal(result.calls[0].url, 'https://seo.example.com/status');
  assert.equal(result.calls[0].options.method, 'GET');
  assert.equal(new Headers(result.calls[0].options.headers).get('authorization'), `Bearer ${TOKEN}`);
});

test('SEO CLI help works without a deployment or credentials', async () => {
  const result = await invoke(['--help'], { env: {} });
  assert.equal(result.code, 0);
  assert.match(result.stdout, /SEO_AGENT_TOKEN/);
  assert.equal(result.calls.length, 0);
});

test('SEO CLI uses explicit config relative to cwd and environment URL takes precedence', async t => {
  const cwd = await configFixture(t, { version: 1, url: 'https://configured.example.com', timeoutMs: 3000 });
  const configured = await invoke(['--config', 'seo.json'], { cwd, env: { SEO_AGENT_TOKEN: TOKEN } });
  assert.equal(configured.code, 0, configured.stderr);
  assert.equal(configured.calls[0].url, 'https://configured.example.com/status');
  const overridden = await invoke(['--config', 'seo.json'], { cwd });
  assert.equal(overridden.code, 0, overridden.stderr);
  assert.equal(overridden.calls[0].url, 'https://seo.example.com/status');
});

test('SEO CLI rejects embedded config secrets and invalid configuration before connecting', async t => {
  for (const config of [
    { version: 1, url: ENV.SEO_AGENT_URL, timeoutMs: 15000, token: TOKEN },
    { version: 2, url: ENV.SEO_AGENT_URL, timeoutMs: 15000 },
    { version: 1, url: ENV.SEO_AGENT_URL, timeoutMs: 0 },
    { version: 1, url: ENV.SEO_AGENT_URL, timeoutMs: 120001 },
  ]) {
    const cwd = await configFixture(t, config);
    const result = await invoke(['--config', 'seo.json'], { cwd });
    assert.equal(result.code, 1);
    assert.equal(result.calls.length, 0);
    assert.doesNotMatch(result.stderr, new RegExp(TOKEN));
  }
});

test('SEO CLI reports unreadable and malformed config without exposing its contents', async t => {
  const cwd = await configFixture(t, {});
  await writeFile(path.join(cwd, 'seo.json'), TOKEN);
  for (const file of ['seo.json', 'missing.json']) {
    const result = await invoke(['--config', file], { cwd });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Cannot read SEO agent configuration/);
    assert.equal(result.calls.length, 0);
    assert.ok(!result.stderr.includes(TOKEN));
  }
});

test('SEO CLI requires a configured URL and environment token without making requests', async () => {
  for (const env of [{}, { SEO_AGENT_URL: ENV.SEO_AGENT_URL }, { SEO_AGENT_TOKEN: TOKEN }]) {
    const result = await invoke([], { env });
    assert.equal(result.code, 1);
    assert.equal(result.calls.length, 0);
  }
});

test('SEO CLI routes filtered findings and proposals to their upstream status query', async () => {
  for (const [command, status] of [['findings', 'dismissed'], ['proposals', 'approved']]) {
    const result = await invoke([command, '--status', status], { body: [] });
    assert.equal(result.code, 0, result.stderr);
    const url = new URL(result.calls[0].url);
    assert.equal(url.pathname, `/${command}`);
    assert.equal(url.searchParams.get('status'), status);
    assert.equal(result.calls[0].options.method, 'GET');
  }
});

test('SEO CLI actions issue exactly one matching POST and preserve upstream JSON', async () => {
  for (const [args, endpoint, body, status] of [
    [['run'], '/run', { started: true, running: true }, 202],
    [['approve', '--id', '7'], '/proposals/7/approve', { ok: true, id: 7, status: 'approved', changeId: 9 }, 200],
    [['reject', '--id', '7'], '/proposals/7/reject', { ok: true, id: 7, status: 'rejected' }, 200],
    [['revert', '--id', '9'], '/changes/9/revert', { ok: true }, 200],
  ]) {
    const result = await invoke(args, { body, status });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.calls.length, 1);
    assert.equal(new URL(result.calls[0].url).pathname, endpoint);
    assert.equal(result.calls[0].options.method, 'POST');
    assert.deepEqual(JSON.parse(result.stdout), body);
  }
});

test('SEO CLI rejects ambiguous or invalid action arguments before connecting', async () => {
  for (const args of [
    ['approve'], ['approve', '--id', '0'], ['revert', '--id', '9007199254740992'],
    ['reject', '--id', '1.5'], ['reject', '--id', '-1'], ['status', '--id', '1'],
    ['run', '--status', 'open'], ['status', 'run'], ['--token', TOKEN],
    ['--config'], ['--id', '1', '--id', '2'], ['--help', 'run'],
    ['findings', '--status', 'unknown'], ['proposals', '--status', 'open'],
  ]) {
    const result = await invoke(args);
    assert.equal(result.code, 1, `Accepted ${JSON.stringify(args)}`);
    assert.equal(result.calls.length, 0);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes(TOKEN));
  }
});

test('SEO CLI surfaces a busy crawl without retries or claiming completion', async () => {
  const result = await invoke(['run'], { status: 409, body: { started: false, running: true } });
  assert.equal(result.code, 1);
  assert.equal(result.calls.length, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /already in progress/i);
});

test('SEO CLI redacts the token from successful JSON, including JSON-escaped token text', async () => {
  const token = 'fixture-"quoted\\token';
  const result = await invoke([], {
    env: { ...ENV, SEO_AGENT_TOKEN: token },
    body: { ...STATUS, reflected: token },
  });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).reflected, '[REDACTED]');
  assert.ok(!result.stdout.includes(token));
});

test('SEO CLI does not expose transport errors or remote error bodies containing its token', async () => {
  const remote = await invoke([], { status: 401, body: { error: TOKEN } });
  const network = await invoke([], { fetchImpl: async () => { throw new Error(`Failed ${TOKEN}`); } });
  for (const result of [remote, network]) {
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes(TOKEN));
  }
});
