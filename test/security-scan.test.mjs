import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { scanRepository, loadSecurityPolicy, SecurityScanError, findCredentialFindings } from '../src/lib/security-scan.mjs';
import { main } from '../src/security-scan.mjs';

const baseline = {
  version: 1,
  name: 'dune-sub-baseline',
  target: 'emptyncrypt-hue',
  maxFileBytes: 5242880,
  excludedDirectories: ['.git', 'node_modules', 'dist', 'generated', '.terraform', '__pycache__'],
};

// Assemble synthetic matching strings at runtime so no full credential-shaped fixture is committed.
function syntheticCredentials() {
  return [
    ['github-token', ['gh', 'p_'].join('') + 'A'.repeat(36)],
    ['github-fine-grained-token', ['github', '_pat_'].join('') + 'B'.repeat(22) + '_' + 'C'.repeat(59)],
    ['openai-api-token', ['s', 'k-'].join('') + 'D'.repeat(48)],
    ['openai-api-token', ['s', 'k-', 'proj-'].join('') + 'E'.repeat(80)],
    ['openai-api-token', ['s', 'k-', 'svcacct-'].join('') + 'F'.repeat(80)],
    ['aws-access-key-id', ['A', 'K', 'I', 'A'].join('') + 'G'.repeat(16)],
    ['aws-access-key-id', ['A', 'S', 'I', 'A'].join('') + 'H'.repeat(16)],
    ['pem-private-key', ['-----', 'BEGIN ', 'RSA ', 'PRIVATE KEY', '-----'].join('')],
  ];
}

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ecosystem-security-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function put(root, relativePath, content) {
  const destination = path.join(root, relativePath);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, content);
}

async function runCli(args) {
  const response = { status: null, stdout: '', stderr: '' };
  response.status = await main(args, {
    stdout: { write: value => { response.stdout += value; } },
    stderr: { write: value => { response.stderr += value; } },
  });
  return response;
}

test('pure credential matcher returns deterministic redacted findings and deduplicates per line', () => {
  const credentials = syntheticCredentials();
  const text = credentials.map(([, value]) => `first=${value} second=${value}`).join('\n');
  const expected = credentials.map(([rule], index) => ({ path: 'bundle/source.txt', line: index + 1, rule }));
  const findings = findCredentialFindings(text, 'bundle/source.txt');
  assert.deepEqual(findings, expected);
  assert.deepEqual(findCredentialFindings(text, 'bundle/source.txt'), findings);
  for (const [, value] of credentials) assert.equal(JSON.stringify(findings).includes(value), false);
  assert.deepEqual(findCredentialFindings('Authorization: Bearer eyJhbGciOi...', 'example.txt'), []);
});

test('detects all baseline credential patterns with stable path/line/rule-only findings', async t => {
  const root = await fixture(t);
  const credentials = syntheticCredentials();
  await put(root, 'nested/credentials.txt', credentials.map(([, value]) => `value=${value}`).join('\n'));
  const result = await scanRepository({ root });
  assert.equal(result.ok, false);
  assert.equal(result.scannedFiles, 1);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.findings, credentials.map(([rule], index) => ({ path: 'nested/credentials.txt', line: index + 1, rule })));
  const serialized = JSON.stringify(result);
  for (const [, value] of credentials) assert.equal(serialized.includes(value), false);
  assert.deepEqual(await scanRepository({ root }), result);
});

test('CLI fails on findings and never echoes credentials or file contents', async t => {
  const root = await fixture(t);
  const [, value] = syntheticCredentials()[0];
  await put(root, 'key.txt', `sensitive-content ${value}`);
  const response = await runCli(['--root', root, '--target=emptyncrypt-hue', '--policy=dune-sub-baseline']);
  assert.equal(response.status, 1);
  assert.equal(response.stderr, '');
  assert.equal(response.stdout.includes(value), false);
  assert.equal(response.stdout.includes('sensitive-content'), false);
  assert.deepEqual(JSON.parse(response.stdout).findings, [{ path: 'key.txt', line: 1, rule: 'github-token' }]);
});

test('flags environment and Wrangler secret files regardless of ignore metadata, with example templates exempt', async t => {
  const root = await fixture(t);
  const sensitivePaths = ['.dev.vars', '.dev.vars.', '.dev.vars.production', '.env', '.env.production', 'nested/.dev.vars.local', 'nested/.env.local'];
  await put(root, '.gitignore', sensitivePaths.join('\n') + '\n');
  for (const file of sensitivePaths) await put(root, file, 'PASSWORD=replace-me');
  await put(root, '.env.example', 'OPENAI_API_KEY=replace-me');
  await put(root, '.dev.vars.example', 'AGENT_TOKEN=replace-me');
  await put(root, '.git/info/exclude', '.env\n');
  const result = await scanRepository({ root });
  assert.deepEqual(result.findings, sensitivePaths.map(file => ({ path: file, line: 1, rule: 'sensitive-env-file' })));
  assert.deepEqual(result.errors, []);
});

test('skips the documented excluded directories while still scanning source and test files', async t => {
  const root = await fixture(t);
  const [, value] = syntheticCredentials()[0];
  for (const folder of baseline.excludedDirectories) await put(root, `${folder}/key.txt`, value);
  await put(root, 'nested/generated/key.txt', value);
  await put(root, 'nested/.terraform/provider/key.txt', value);
  await put(root, 'nested/__pycache__/module.txt', value);
  await put(root, 'test/fixture.txt', value);
  await put(root, 'src/config.txt', value);
  const result = await scanRepository({ root });
  assert.equal(result.scannedFiles, 2);
  assert.deepEqual(result.findings.map(finding => finding.path), ['src/config.txt', 'test/fixture.txt']);
});

test('permits harmless placeholders and historical partial bearer tokens', async t => {
  const root = await fixture(t);
  await put(root, '.env.example', 'OPENAI_API_KEY=replace-me\nGITHUB_TOKEN=<token>\n');
  await put(root, '.dev.vars.example', 'AGENT_TOKEN=replace-me\n');
  await put(root, 'docs/example.txt', 'Authorization: Bearer eyJhbGciOi...\nghp_<placeholder>\nsk-proj-<replace-with-key>\nAKIA<example>\n');
  const result = await scanRepository({ root });
  assert.equal(result.ok, true);
  assert.equal(result.target, baseline.target);
  assert.deepEqual(result.findings, []);
});

test('rejects file and directory symlinks without following links outside the root', async t => {
  const root = await fixture(t);
  const outside = await fixture(t);
  const [, value] = syntheticCredentials()[0];
  await put(outside, 'key.txt', value);
  await symlink(path.join(outside, 'key.txt'), path.join(root, 'linked.txt'));
  await symlink(outside, path.join(root, 'linked-dir'), 'dir');
  const result = await scanRepository({ root });
  assert.equal(result.ok, false);
  assert.equal(result.scannedFiles, 0);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.errors, [
    { path: 'linked-dir', line: 1, rule: 'symlink' },
    { path: 'linked.txt', line: 1, rule: 'symlink' },
  ]);
});

test('rejects symlinked roots and symlinked root ancestors', async t => {
  const parent = await fixture(t);
  const root = await fixture(t);
  await put(root, 'sub/clean.txt', 'hello');
  const linked = path.join(parent, 'linked');
  await symlink(root, linked, 'dir');
  for (const unsafeRoot of [linked, path.join(linked, 'sub')]) {
    const result = await scanRepository({ root: unsafeRoot });
    assert.deepEqual(result.errors, [{ path: '.', line: 1, rule: 'unsafe-root' }]);
    assert.equal(result.scannedFiles, 0);
  }
});

test('skips binary files and detects credentials in BOM-marked UTF-16 text', async t => {
  const root = await fixture(t);
  const [, value] = syntheticCredentials()[0];
  await put(root, 'binary.bin', Buffer.from([0, 1, 2, 255]));
  await put(root, 'unicode.txt', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`first\n${value}`, 'utf16le')]));
  const result = await scanRepository({ root });
  assert.equal(result.skippedBinaryFiles, 1);
  assert.equal(result.scannedFiles, 1);
  assert.deepEqual(result.findings, [{ path: 'unicode.txt', line: 2, rule: 'github-token' }]);
});

test('oversized files cause failure rather than a silent incomplete scan', async t => {
  const root = await fixture(t);
  const policyDirectory = await fixture(t);
  const policyPath = path.join(policyDirectory, 'policy.json');
  await writeFile(policyPath, JSON.stringify({ ...baseline, maxFileBytes: 64 }));
  await put(root, 'large.txt', 'x'.repeat(65));
  await put(root, 'normal.txt', 'x'.repeat(64));
  const result = await scanRepository({ root, policyPath });
  assert.equal(result.ok, false);
  assert.equal(result.scannedFiles, 1);
  assert.deepEqual(result.errors, [{ path: 'large.txt', line: 1, rule: 'file-size-limit' }]);
});

test('unknown, malformed, weakened, and unsupported policies fail closed', async t => {
  const root = await fixture(t);
  const policyPath = path.join(root, 'policy.json');
  await assert.rejects(loadSecurityPolicy(undefined, 'unknown'), SecurityScanError);
  await writeFile(policyPath, '{"credential":"do-not-echo"');
  await assert.rejects(loadSecurityPolicy(policyPath), error => error instanceof SecurityScanError && !error.message.includes('do-not-echo'));
  for (const policy of [
    { ...baseline, version: 2 },
    { ...baseline, excludedDirectories: [...baseline.excludedDirectories, 'src'] },
    { ...baseline, maxFileBytes: 0 },
    { ...baseline, target: '../outside' },
    { ...baseline, extra: true },
  ]) {
    await writeFile(policyPath, JSON.stringify(policy));
    await assert.rejects(loadSecurityPolicy(policyPath), SecurityScanError);
  }
  await assert.rejects(scanRepository({ root, target: 'different-owner' }), SecurityScanError);
});

test('CLI help, clean exit, invalid arguments, unknown policy, and invalid root have clear statuses', async t => {
  const root = await fixture(t);
  await put(root, 'clean.txt', 'hello');
  const help = await runCli(['--help']);
  assert.equal(help.status, 0);
  assert.match(help.stdout, /Git history/);
  assert.equal((await runCli(['--root', root])).status, 0);
  for (const args of [['--policy', 'unknown'], ['--bad'], ['constructor', 'value'], ['__proto__', 'value'], ['--root'], ['--root', root, '--root', root]]) {
    const response = await runCli(args);
    assert.equal(response.status, 2);
    assert.match(response.stderr, /^security-scan:/);
  }
  const response = await runCli(['--root', path.join(root, 'missing')]);
  assert.equal(response.status, 1);
  assert.deepEqual(JSON.parse(response.stdout).errors, [{ path: '.', line: 1, rule: 'unreadable-root' }]);
});
