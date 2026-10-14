import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { safeRelativePath, validateBundle, validatePolicies, validateRepository } from '../src/lib/validation.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const policies = {
  schemaVersion: 1,
  target: { owner: 'emptyncrypt-hue', repository: 'Ecosystem', branch: 'main' },
  integrity: { algorithm: 'sha256', rejectSymlinks: true },
  limits: { maxFiles: 100, maxFileBytes: 1024, maxTotalBytes: 4096 },
};
const file = (name, content) => ({ path: name, mode: '100644', content, bytes: Buffer.byteLength(content), sha256: hash(content) });
const bundle = () => ({ schemaVersion: 1, target: { ...policies.target }, files: [file('source.txt', 'valid payload\n')] });

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'dunesub-validation-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'config'));
  await mkdir(path.join(root, 'docs'));
  await writeFile(path.join(root, 'config/gateway-policies.json'), JSON.stringify(policies));
  await writeFile(path.join(root, 'source.txt'), 'valid payload\n');
  const manifest = { schema_version: 1, documents: [], source_files: [{ path: 'source.txt', size_bytes: 14, sha256: hash('valid payload\n') }] };
  await writeFile(path.join(root, 'docs/source_manifest.json'), JSON.stringify(manifest));
  return { root, manifest };
}

test('source artifact tampering fails both byte-count and digest checks', async t => {
  const { root } = await fixture(t);
  assert.equal((await validateRepository(root)).ok, true);
  await writeFile(path.join(root, 'source.txt'), 'changed source');
  const result = await validateRepository(root);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => error.includes('SHA-256 mismatch')));
});

test('missing artifacts and symlink ancestors cannot pass repository verification', async t => {
  const { root, manifest } = await fixture(t);
  manifest.source_files[0].path = 'missing.txt';
  await writeFile(path.join(root, 'docs/source_manifest.json'), JSON.stringify(manifest));
  assert.equal((await validateRepository(root)).ok, false);
  const external = await mkdtemp(path.join(os.tmpdir(), 'dunesub-external-'));
  t.after(() => rm(external, { recursive: true, force: true }));
  await writeFile(path.join(external, 'source.txt'), 'valid payload\n');
  await symlink(external, path.join(root, 'outside'));
  manifest.source_files[0].path = 'outside/source.txt';
  await writeFile(path.join(root, 'docs/source_manifest.json'), JSON.stringify(manifest));
  assert.ok((await validateRepository(root)).errors.some(error => error.includes('Symlink')));
});

test('manifest rejects path traversal, duplicates, and invalid digest metadata', async t => {
  const { root, manifest } = await fixture(t);
  manifest.source_files.push({ ...manifest.source_files[0] }, { path: '../source.txt', size_bytes: 1, sha256: 'x' });
  await writeFile(path.join(root, 'docs/source_manifest.json'), JSON.stringify(manifest));
  const result = await validateRepository(root);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => error.includes('Duplicate')));
  assert.ok(result.errors.some(error => error.includes('unsafe')));
});

test('oversized artifacts fail at the reader boundary even with matching manifest hashes', async t => {
  const { root, manifest } = await fixture(t);
  const data = 'x'.repeat(policies.limits.maxFileBytes + 1);
  await writeFile(path.join(root, 'source.txt'), data);
  manifest.source_files[0].size_bytes = data.length;
  manifest.source_files[0].sha256 = hash(data);
  await writeFile(path.join(root, 'docs/source_manifest.json'), JSON.stringify(manifest));
  const result = await validateRepository(root);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => error.includes('File exceeds byte limit')));
});

test('repository policy rejects weaker integrity settings and inconsistent limits', () => {
  const modified = structuredClone(policies);
  modified.integrity.rejectSymlinks = false;
  modified.limits.maxFileBytes = modified.limits.maxTotalBytes + 1;
  assert.equal(validatePolicies(modified).ok, false);
  assert.equal(validatePolicies({ ...policies, unexpected: true }).ok, false);
});

test('bundle validates multibyte byte counts and detects mutated contents', () => {
  const value = bundle();
  value.files = [file('unicode.txt', 'Dune-Sub ✓')];
  assert.equal(validateBundle(value, policies).ok, true);
  value.files[0].content += ' tampered';
  assert.equal(validateBundle(value, policies).ok, false);
});

test('bundle rejects wrong targets, duplicates, size-limit bypass and secret-file paths', () => {
  const value = bundle();
  value.target.owner = 'other-owner';
  value.files.push({ ...value.files[0] }, file('.env', 'example=value'));
  assert.equal(validateBundle(value, policies).ok, false);
  const tooLarge = bundle();
  tooLarge.files = [file('large.txt', 'a'.repeat(1025))];
  assert.equal(validateBundle(tooLarge, policies).ok, false);
});

test('malformed refs and unpaired Unicode surrogates are rejected', () => {
  const value = bundle();
  value.target.branch = 'main.lock';
  assert.equal(validateBundle(value, policies).ok, false);
  value.target.branch = 'main';
  value.files = [file('source.txt', '\ud800')];
  assert.equal(validateBundle(value, policies).ok, false);
});

test('target identifiers must be primitive strings and valid UTF-8 BOM is preserved', () => {
  for (const bad of [42, null, {}, true, undefined]) {
    const value = bundle();
    value.target.owner = bad;
    assert.equal(validateBundle(value).ok, false);
    value.target.owner = policies.target.owner;
    value.target.repository = bad;
    assert.equal(validateBundle(value).ok, false);
  }
  const value = bundle();
  value.files = [file('bom.txt', '\ufeffDune-Sub')];
  assert.equal(validateBundle(value, policies).ok, true);
});

test('repository paths reject metadata, backslashes, absolute paths, and control characters', () => {
  for (const value of ['../source', '/source', '.git/config', 'nested/.git/token', 'a\\b', 'a\nb', 'a//b', 'C:/file']) {
    assert.equal(safeRelativePath(value), false, value);
  }
  assert.equal(safeRelativePath('.github/workflows/verify.yml'), true);
});

test('bundle credential detection rejects publication without revealing the matched secret', () => {
  const secret = ['ghp', '_', 'Q'.repeat(36)].join('');
  const value = bundle();
  value.files = [file('source.txt', `credential=${secret}`)];
  const result = validateBundle(value, policies);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => error.includes('github-token')));
  assert.ok(result.errors.every(error => !error.includes(secret)));
});

test('bundled artifacts must match their embedded provenance manifest', () => {
  const value = bundle();
  const manifest = { schema_version: 1, documents: [], source_files: [{ path: 'source.txt', size_bytes: value.files[0].bytes, sha256: value.files[0].sha256 }] };
  value.files.push(file('docs/source_manifest.json', JSON.stringify(manifest)));
  assert.equal(validateBundle(value, policies).ok, true);
  value.files[0] = file('source.txt', 'changed after initial validation');
  assert.equal(validateBundle(value, policies).ok, false);
  value.files.shift();
  assert.equal(validateBundle(value, policies).ok, false);
  for (const invalid of ['null', 'false', '0']) {
    value.files = [file('docs/source_manifest.json', invalid)];
    assert.equal(validateBundle(value, policies).ok, false);
  }
});
