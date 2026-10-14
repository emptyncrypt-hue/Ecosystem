import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createBundle, pushBundle, writeBundle } from '../src/lib/sync.mjs';
import { runCli } from '../src/dune-sync.mjs';

const execFileAsync = promisify(execFile);
const HEAD = 'a'.repeat(40);
const BASE_TREE = 'b'.repeat(40);
const TREE = 'c'.repeat(40);
const COMMIT = 'd'.repeat(40);
const policies = {
  schemaVersion: 1,
  target: { owner: 'example-owner', repository: 'Ecosystem', branch: 'main' },
  limits: { maxFiles: 100, maxFileBytes: 1024 * 1024, maxTotalBytes: 4 * 1024 * 1024 },
  integrity: { algorithm: 'sha256', rejectSymlinks: true },
};

async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dune-sync-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await execFileAsync('git', ['init', '-q'], { cwd: directory });
  await fs.mkdir(path.join(directory, 'config'));
  await fs.mkdir(path.join(directory, 'docs'));
  await fs.writeFile(path.join(directory, 'config/gateway-policies.json'), JSON.stringify(policies));
  await fs.writeFile(path.join(directory, 'docs/source_manifest.json'), JSON.stringify({ schema_version: 1, documents: [], source_files: [] }));
  await fs.writeFile(path.join(directory, '.gitignore'), 'dist/\ngenerated/\nnode_modules/\nignored.txt\n');
  await fs.writeFile(path.join(directory, 'tracked.txt'), 'tracked\n');
  await execFileAsync('git', ['add', '.'], { cwd: directory });
  return directory;
}

function sampleBundle() {
  const content = 'source\n';
  return {
    schemaVersion: 1, target: { ...policies.target },
    files: [{ path: 'src/example.mjs', mode: '100644', content, sha256: createHash('sha256').update(content).digest('hex'), bytes: Buffer.byteLength(content) }],
  };
}

function mockTransport(replies) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, ...options, body: options.body ? JSON.parse(options.body) : undefined });
    assert.ok(replies.length, 'unexpected API request');
    const next = replies.shift();
    if (next instanceof Error) throw next;
    return new Response(JSON.stringify(next.body), { status: next.status ?? 200, headers: { 'Content-Type': 'application/json' } });
  };
  return { calls, fetchImpl };
}

function successfulReplies({ reread = HEAD, patchStatus = 200 } = {}) {
  return [
    { body: { object: { sha: HEAD } } },
    { body: { sha: HEAD, tree: { sha: BASE_TREE } } },
    { status: 201, body: { sha: TREE } },
    { status: 201, body: { sha: COMMIT } },
    { body: { object: { sha: reread } } },
    { status: patchStatus, body: { object: { sha: COMMIT } } },
  ];
}

test('bundle includes unique sorted Git files, exact UTF-8 bytes and hashes; ignores generated files', async (t) => {
  const root = await fixture(t);
  const unicode = '\uFEFFHello, Dune-Sub 🌍\r\n';
  await fs.writeFile(path.join(root, 'z-untracked.txt'), unicode);
  await fs.writeFile(path.join(root, 'ignored.txt'), 'ignored');
  await fs.mkdir(path.join(root, 'dist'));
  await fs.writeFile(path.join(root, 'dist/ecosystem-sync.json'), 'previous bundle');
  const first = await createBundle(root);
  const second = await createBundle(root);
  assert.deepEqual(first, second);
  const paths = first.files.map((file) => file.path);
  assert.deepEqual(paths, [...new Set(paths)].sort());
  assert.ok(paths.includes('tracked.txt'));
  assert.ok(paths.includes('z-untracked.txt'));
  assert.ok(!paths.includes('ignored.txt'));
  assert.ok(!paths.includes('dist/ecosystem-sync.json'));
  const file = first.files.find((entry) => entry.path === 'z-untracked.txt');
  assert.equal(file.content, unicode);
  assert.equal(file.bytes, Buffer.byteLength(unicode));
  assert.equal(file.sha256, createHash('sha256').update(unicode).digest('hex'));
  assert.equal(file.mode, '100644');
});

test('explicit output is excluded to avoid bundling an earlier bundle', async (t) => {
  const root = await fixture(t);
  await fs.writeFile(path.join(root, 'bundle.json'), 'older output');
  const bundle = await createBundle(root, { excludePaths: ['bundle.json'] });
  assert.ok(!bundle.files.some((file) => file.path === 'bundle.json'));
});

test('verification metadata cannot be ignored or explicitly excluded from source bundles', async (t) => {
  const root = await fixture(t);
  await assert.rejects(createBundle(root, { excludePaths: ['config/gateway-policies.json'] }), /must include verification metadata/);
  await assert.rejects(createBundle(root, { snapshot: true, excludePaths: ['docs/source_manifest.json'] }), /must include verification metadata/);
  await execFileAsync('git', ['rm', '--cached', '-q', 'config/gateway-policies.json', 'docs/source_manifest.json'], { cwd: root });
  await fs.appendFile(path.join(root, '.gitignore'), 'config/gateway-policies.json\ndocs/source_manifest.json\n');
  await assert.rejects(createBundle(root), /must include verification metadata/);
});

test('explicit snapshot mode handles Cloud Build source without .git and excludes generated directories', async (t) => {
  const root = await fixture(t);
  await fs.rm(path.join(root, '.git'), { recursive: true });
  await fs.writeFile(path.join(root, 'provided-source.custom-extension'), 'source from tar\n');
  for (const name of ['node_modules', 'dist', 'generated', '.terraform', '__pycache__']) {
    await fs.mkdir(path.join(root, name));
    await fs.writeFile(path.join(root, name, 'ignored.bin'), Buffer.from([0xff]));
  }
  await fs.writeFile(path.join(root, 'output.json'), 'previous output');
  await assert.rejects(createBundle(root), /Unable to enumerate repository files with Git/);
  const first = await createBundle(root, { snapshot: true, excludePaths: ['output.json'] });
  const second = await createBundle(root, { snapshot: true, excludePaths: ['output.json'] });
  assert.deepEqual(first, second);
  assert.ok(first.files.some((file) => file.path === 'provided-source.custom-extension'));
  assert.ok(!first.files.some((file) => file.path === 'output.json' || file.path.endsWith('ignored.bin')));
  let output = '';
  assert.equal(await runCli(['--snapshot'], { cwd: root, env: {}, stdout: { write: (text) => { output += text; } }, stderr: { write: () => assert.fail('unexpected error') } }), 0);
  assert.match(output, /Wrote \d+ verified files/);
});

test('snapshot mode rejects symlinks, unsafe paths, secret env files and unknown binary files', async (t) => {
  const root = await fixture(t);
  await fs.symlink(path.join(root, 'tracked.txt'), path.join(root, 'link.txt'));
  await assert.rejects(createBundle(root, { snapshot: true }), /symlink/i);
  await fs.rm(path.join(root, 'link.txt'));
  await fs.writeFile(path.join(root, 'bad\\name.txt'), 'unsafe');
  await assert.rejects(createBundle(root, { snapshot: true }), /unsafe file path/i);
  await fs.rm(path.join(root, 'bad\\name.txt'));
  await fs.writeFile(path.join(root, '.env'), 'API_KEY=example\n');
  await assert.rejects(createBundle(root, { snapshot: true }), /Environment secret files/);
  await fs.rm(path.join(root, '.env'));
  await fs.writeFile(path.join(root, 'unknown.dat'), Buffer.from([0xff]));
  await assert.rejects(createBundle(root, { snapshot: true }), /UTF-8/i);
});

test('symlinked files and tracked paths below a symlink are rejected', async (t) => {
  const root = await fixture(t);
  const outside = path.join(path.dirname(root), `${path.basename(root)}-outside.txt`);
  t.after(() => fs.rm(outside, { force: true }));
  await fs.writeFile(outside, 'external');
  await fs.symlink(outside, path.join(root, 'link.txt'));
  await assert.rejects(createBundle(root), /symlink/i);
  await fs.rm(path.join(root, 'link.txt'));
  await fs.mkdir(path.join(root, 'nested'));
  await fs.writeFile(path.join(root, 'nested/file.txt'), 'safe');
  await execFileAsync('git', ['add', 'nested/file.txt'], { cwd: root });
  await fs.rm(path.join(root, 'nested'), { recursive: true });
  await fs.symlink(path.dirname(outside), path.join(root, 'nested'));
  await assert.rejects(createBundle(root), /symlink/i);
});

test('unsafe POSIX paths and invalid UTF-8 content are rejected', async (t) => {
  const root = await fixture(t);
  await fs.writeFile(path.join(root, 'bad\\name.txt'), 'safe text');
  await assert.rejects(createBundle(root), /unsafe file path/i);
  await fs.rm(path.join(root, 'bad\\name.txt'));
  await fs.writeFile(path.join(root, 'invalid.bin'), Buffer.from([0xff, 0xfe]));
  await assert.rejects(createBundle(root), /UTF-8/i);
});

test('tracked files replaced with named pipes are rejected without opening them', { skip: process.platform === 'win32' }, async (t) => {
  const root = await fixture(t);
  await fs.rm(path.join(root, 'tracked.txt'));
  await execFileAsync('mkfifo', [path.join(root, 'tracked.txt')]);
  await assert.rejects(createBundle(root), /Only regular files/);
});

test('size limits and destinations are enforced before uploading', async (t) => {
  const root = await fixture(t);
  await fs.writeFile(path.join(root, 'large.txt'), 'x'.repeat(2000));
  await assert.rejects(createBundle(root, { policies: { ...policies, limits: { ...policies.limits, maxFileBytes: 1024 } } }), /maxFileBytes/);
  await assert.rejects(createBundle(root, { policies: { ...policies, limits: { ...policies.limits, maxFiles: 1 } } }), /maxFiles/);
  await assert.rejects(createBundle(root, { policies: { ...policies, limits: { ...policies.limits, maxTotalBytes: 1024 } } }), /maxTotalBytes/);
  await assert.rejects(createBundle(root, { target: { ...policies.target, repository: 'wrong-repo' } }), /destination must match/i);
});

test('push preserves the base tree and creates exact-parent commit with force disabled', async () => {
  const { calls, fetchImpl } = mockTransport(successfulReplies());
  const bundle = sampleBundle();
  const receipt = await pushBundle(bundle, { token: 'test-secret', expectedHead: HEAD, policies, fetchImpl });
  assert.deepEqual(calls.map((call) => call.method), ['GET', 'GET', 'POST', 'POST', 'GET', 'PATCH']);
  assert.equal(calls[0].url, 'https://api.github.com/repos/example-owner/Ecosystem/git/ref/heads/main');
  assert.equal(calls[1].url, `https://api.github.com/repos/example-owner/Ecosystem/git/commits/${HEAD}`);
  assert.deepEqual(calls[2].body, {
    base_tree: BASE_TREE,
    tree: [{ path: 'src/example.mjs', mode: '100644', type: 'blob', content: 'source\n' }],
  });
  assert.deepEqual(calls[3].body.parents, [HEAD]);
  assert.equal(calls[3].body.tree, TREE);
  assert.deepEqual(calls[5].body, { sha: COMMIT, force: false });
  assert.equal(calls[5].url, 'https://api.github.com/repos/example-owner/Ecosystem/git/refs/heads/main');
  assert.equal(calls[0].redirect, 'error');
  assert.equal(calls[0].headers.Authorization, 'Bearer test-secret');
  assert.equal(receipt.commitSha, COMMIT);
  assert.equal(receipt.treeSha, TREE);
  assert.equal(receipt.url, `https://github.com/example-owner/Ecosystem/commit/${COMMIT}`);
  assert.ok(!JSON.stringify(receipt).includes('test-secret'));
});

test('a mismatched expected head sends no write requests', async () => {
  const { calls, fetchImpl } = mockTransport([{ body: { object: { sha: 'f'.repeat(40) } } }]);
  await assert.rejects(pushBundle(sampleBundle(), { token: 'secret', expectedHead: HEAD, policies, fetchImpl }), /differs from --expected-head/);
  assert.deepEqual(calls.map((call) => call.method), ['GET']);
});

test('head changes during bundle upload leave the new commit unattached', async () => {
  const { calls, fetchImpl } = mockTransport(successfulReplies({ reread: 'f'.repeat(40) }));
  await assert.rejects(pushBundle(sampleBundle(), { token: 'secret', expectedHead: HEAD, policies, fetchImpl }), /branch changed/);
  assert.ok(!calls.some((call) => call.method === 'PATCH'));
});

test('a race rejected by GitHub never retries with force', async () => {
  const { calls, fetchImpl } = mockTransport(successfulReplies({ patchStatus: 422 }));
  await assert.rejects(pushBundle(sampleBundle(), { token: 'secret', expectedHead: HEAD, policies, fetchImpl }), /HTTP 422/);
  assert.equal(calls.length, 6);
  assert.deepEqual(calls.at(-1).body, { sha: COMMIT, force: false });
});

test('auth and transport errors neither expose tokens nor attempt writes', async () => {
  const token = 'github_pat_super_secret';
  const auth = mockTransport([{ status: 403, body: { message: `restricted ${token}` } }]);
  await assert.rejects(pushBundle(sampleBundle(), { token, expectedHead: HEAD, policies, fetchImpl: auth.fetchImpl }), (error) => {
    assert.match(error.message, /HTTP 403/);
    assert.ok(!error.message.includes(token));
    return true;
  });
  assert.deepEqual(auth.calls.map((call) => call.method), ['GET']);
  const transport = mockTransport([new Error(`connection failed for Bearer ${token}`)]);
  await assert.rejects(pushBundle(sampleBundle(), { token, expectedHead: HEAD, policies, fetchImpl: transport.fetchImpl }), (error) => {
    assert.ok(!error.message.includes(token));
    return true;
  });
});

test('invalid payloads and invalid expected-head fail before network requests', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error('must not be called'); };
  const invalid = sampleBundle();
  invalid.files[0].content = 'tampered';
  await assert.rejects(pushBundle(invalid, { token: 'secret', expectedHead: HEAD, policies, fetchImpl }), /Bundle validation failed/);
  const traversal = sampleBundle();
  traversal.files[0].path = '../outside.txt';
  await assert.rejects(pushBundle(traversal, { token: 'secret', expectedHead: HEAD, policies, fetchImpl }), /Bundle validation failed/);
  await assert.rejects(pushBundle(sampleBundle(), { token: 'secret', expectedHead: 'short', policies, fetchImpl }), /40-character/);
  assert.equal(calls, 0);
});

test('invalid GitHub responses do not report success', async () => {
  const invalid = mockTransport([{ body: { object: { sha: 'not-a-sha' } } }]);
  await assert.rejects(pushBundle(sampleBundle(), { token: 'secret', expectedHead: HEAD, policies, fetchImpl: invalid.fetchImpl }), /invalid branch head/);
  const replies = successfulReplies();
  replies.at(-1).body.object.sha = 'e'.repeat(40);
  const unconfirmed = mockTransport(replies);
  await assert.rejects(pushBundle(sampleBundle(), { token: 'secret', expectedHead: HEAD, policies, fetchImpl: unconfirmed.fetchImpl }), /did not confirm/);
});

test('CLI default writes a real deterministic bundle without requesting the network', async (t) => {
  const root = await fixture(t);
  let stdout = '';
  let stderr = '';
  const options = { cwd: root, env: {}, stdout: { write: (text) => { stdout += text; } }, stderr: { write: (text) => { stderr += text; } }, fetchImpl: async () => { assert.fail('default command must not access GitHub'); } };
  assert.equal(await runCli([], options), 0);
  const first = await fs.readFile(path.join(root, 'dist/ecosystem-sync.json'), 'utf8');
  assert.ok(JSON.parse(first).files.some((file) => file.path === 'tracked.txt'));
  assert.equal(await runCli([], options), 0);
  assert.equal(await fs.readFile(path.join(root, 'dist/ecosystem-sync.json'), 'utf8'), first);
  assert.equal(stderr, '');
  assert.match(stdout, /Wrote \d+ verified files/);
  assert.ok(!stdout.includes('Pushed'));
});

test('CLI push requires explicit expected-head, redacts token text, and supports help without a repository', async () => {
  const token = 'sensitive-test-token';
  let stdout = '';
  let stderr = '';
  const options = { cwd: '/not/a/repository', env: { GH_TOKEN: token }, stdout: { write: (text) => { stdout += text; } }, stderr: { write: (text) => { stderr += text; } } };
  assert.equal(await runCli(['--help'], options), 0);
  assert.match(stdout, /--expected-head/);
  assert.equal(await runCli(['--push'], options), 1);
  assert.match(stderr, /--expected-head/);
  stderr = '';
  assert.equal(await runCli(['--root', token], options), 1);
  assert.ok(!stderr.includes(token));
});

test('CLI --push uploads the validated bundle using GITHUB_TOKEN and reports the confirmed commit', async (t) => {
  const root = await fixture(t);
  const token = 'cli-only-secret';
  let stdout = '';
  let stderr = '';
  const { calls, fetchImpl } = mockTransport(successfulReplies());
  const code = await runCli([
    '--root', root, '--org', policies.target.owner, '--repo', policies.target.repository,
    '--branch', policies.target.branch, '--output', 'dist/runtime-bundle.json', '--push', '--expected-head', HEAD,
  ], { env: { GITHUB_TOKEN: token }, stdout: { write: (text) => { stdout += text; } }, stderr: { write: (text) => { stderr += text; } }, fetchImpl });
  assert.equal(code, 0);
  const written = JSON.parse(await fs.readFile(path.join(root, 'dist/runtime-bundle.json'), 'utf8'));
  assert.deepEqual(calls[2].body.tree, written.files.map(({ path: filePath, mode, content }) => ({ path: filePath, mode, type: 'blob', content })));
  assert.match(stdout, new RegExp(`Pushed ${COMMIT}`));
  assert.ok(!stdout.includes(token));
  assert.ok(!JSON.stringify(written).includes(token));
  assert.equal(stderr, '');
});

test('CLI redacts authentication tokens even when they appear in output paths', async (t) => {
  const root = await fixture(t);
  const token = 'do-not-log-this-token';
  let stdout = '';
  const code = await runCli(['--output', `dist/${token}.json`], {
    cwd: root, env: { GH_TOKEN: ` ${token} ` }, stdout: { write: (text) => { stdout += text; } }, stderr: { write: () => assert.fail('unexpected error') },
  });
  assert.equal(code, 0);
  assert.ok(!stdout.includes(token));
  assert.match(stdout, /\[REDACTED\]/);
});

test('bundle output cannot follow symlinks', async (t) => {
  const root = await fixture(t);
  const output = path.join(root, 'output.json');
  const target = path.join(root, 'tracked.txt');
  await fs.symlink(target, output);
  await assert.rejects(writeBundle(output, sampleBundle()), /symlink/i);
  assert.equal(await fs.readFile(target, 'utf8'), 'tracked\n');
});
