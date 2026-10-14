import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { loadPolicies, validateBundle, validateRepository } from './validation.mjs';

const execFileAsync = promisify(execFile);
const SHA = /^[a-f0-9]{40}$/i;
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const SNAPSHOT_EXCLUDED_DIRECTORIES = new Set(['.git', 'node_modules', 'dist', 'generated', '.terraform', '__pycache__']);

function failure(message) {
  return new Error(message);
}

function assertSafePath(filePath) {
  if (typeof filePath !== 'string' || !filePath || filePath.includes('\\') ||
      /[\u0000-\u001f\u007f]/u.test(filePath) || path.posix.isAbsolute(filePath) ||
      /^[a-z]:/i.test(filePath) || filePath.split('/').some((part) => !part || part === '.' || part === '..' || part.toLowerCase() === '.git')) {
    throw failure('The repository contains an unsafe file path.');
  }
}

function assertTarget(target, policies) {
  if (!target || !policies?.target || ['owner', 'repository', 'branch'].some((key) => target[key] !== policies.target[key])) {
    throw failure('The destination must match config/gateway-policies.json.');
  }
}

async function readSafeFile(rootDir, filePath, maxFileBytes) {
  assertSafePath(filePath);
  let candidate = rootDir;
  let expected;
  for (const component of filePath.split('/')) {
    candidate = path.join(candidate, component);
    expected = await fs.lstat(candidate);
    if (expected.isSymbolicLink()) {
      throw failure(`Symlinks cannot be synchronized: ${filePath}`);
    }
  }
  if (!expected.isFile()) throw failure(`Only regular files can be synchronized: ${filePath}`);
  if (await fs.realpath(candidate) !== candidate) {
    throw failure(`File escapes the repository root: ${filePath}`);
  }
  const handle = await fs.open(candidate, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw failure(`Only regular files can be synchronized: ${filePath}`);
    if (before.dev !== expected.dev || before.ino !== expected.ino || await fs.realpath(candidate) !== candidate) {
      throw failure(`File changed while creating the bundle: ${filePath}`);
    }
    if (before.size > maxFileBytes) throw failure(`File exceeds maxFileBytes: ${filePath}`);
    // Bound the read even if another process grows the file after its initial stat.
    const buffer = Buffer.alloc(Math.min(before.size, maxFileBytes) + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const bytes = buffer.subarray(0, offset);
    const after = await handle.stat();
    if (bytes.length > maxFileBytes || after.size > maxFileBytes) throw failure(`File exceeds maxFileBytes: ${filePath}`);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== after.size) {
      throw failure(`File changed while creating the bundle: ${filePath}`);
    }
    let content;
    try {
      content = utf8.decode(bytes);
    } catch {
      throw failure(`Only valid UTF-8 files can be synchronized: ${filePath}`);
    }
    return { path: filePath, mode: '100644', content, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
  } finally {
    await handle.close();
  }
}

async function listSnapshotFiles(rootDir, { maxFiles }, excluded) {
  const paths = [];
  let visited = 0;
  async function walk(directory, prefix, depth) {
    if (depth > 64) throw failure('The source snapshot exceeds the directory depth limit.');
    const before = await fs.lstat(directory);
    if (!before.isDirectory() || before.isSymbolicLink() || await fs.realpath(directory) !== directory) {
      throw failure('The source snapshot contains an unsafe directory.');
    }
    const entries = await fs.opendir(directory);
    for await (const entry of entries) {
      if (++visited > maxFiles * 10) throw failure('The source snapshot exceeds the traversal entry limit.');
      // Also omit Git worktree pointer files; no Git metadata belongs in a snapshot.
      if (entry.name === '.git') continue;
      const filePath = prefix ? `${prefix}/${entry.name}` : entry.name;
      assertSafePath(filePath);
      if (excluded.has(filePath)) continue;
      const candidate = path.join(rootDir, filePath);
      const stat = await fs.lstat(candidate);
      if (stat.isSymbolicLink()) throw failure(`Symlinks cannot be synchronized: ${filePath}`);
      if (stat.isDirectory()) {
        if (!SNAPSHOT_EXCLUDED_DIRECTORIES.has(entry.name)) await walk(candidate, filePath, depth + 1);
      } else if (stat.isFile()) {
        paths.push(filePath);
        if (paths.length > maxFiles) throw failure('The source snapshot exceeds maxFiles.');
      } else {
        throw failure(`Only regular files can be synchronized: ${filePath}`);
      }
    }
    const after = await fs.lstat(directory);
    if (after.dev !== before.dev || after.ino !== before.ino || after.isSymbolicLink() || await fs.realpath(directory) !== directory) {
      throw failure('A source snapshot directory changed during traversal.');
    }
  }
  await walk(rootDir, '', 0);
  return paths.sort();
}

/** Default: snapshot Git tracked/nonignored files. Explicit snapshot mode walks a provided source tar. */
export async function createBundle(rootDirectory, { target, policies, excludePaths = [], snapshot = false } = {}) {
  const rootDir = await fs.realpath(rootDirectory);
  const configured = policies ?? await loadPolicies(rootDir);
  const destination = target ?? configured.target;
  assertTarget(destination, configured);
  const repository = await validateRepository(rootDir);
  if (!repository.ok) throw failure(`Repository validation failed: ${repository.errors.join('; ')}`);
  const excluded = new Set(excludePaths);
  let paths;
  if (snapshot) {
    paths = await listSnapshotFiles(rootDir, configured.limits, excluded);
  } else {
    let listed;
    try {
      const topLevel = await execFileAsync('git', ['rev-parse', '--show-toplevel'], { cwd: rootDir, maxBuffer: 1024 * 1024 });
      if (await fs.realpath(topLevel.stdout.trim()) !== rootDir) throw failure('The root must be the Git repository root.');
      listed = (await execFileAsync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
        cwd: rootDir, encoding: 'buffer', maxBuffer: 16 * 1024 * 1024,
      })).stdout;
    } catch (error) {
      if (error.message === 'The root must be the Git repository root.') throw error;
      throw failure('Unable to enumerate repository files with Git.');
    }
    try {
      paths = utf8.decode(listed).split('\0').filter(Boolean);
    } catch {
      throw failure('Git file paths must use valid UTF-8.');
    }
  }
  paths = [...new Set(paths)].filter((filePath) => !excluded.has(filePath)).sort();
  for (const required of ['config/gateway-policies.json', 'docs/source_manifest.json']) {
    if (!paths.includes(required)) throw failure(`The bundle must include verification metadata: ${required}`);
  }
  if (paths.length > configured.limits.maxFiles) throw failure('The repository exceeds maxFiles.');
  const files = [];
  let totalBytes = 0;
  for (const filePath of paths) {
    const file = await readSafeFile(rootDir, filePath, configured.limits.maxFileBytes);
    totalBytes += file.bytes;
    if (totalBytes > configured.limits.maxTotalBytes) throw failure('The repository exceeds maxTotalBytes.');
    files.push(file);
  }
  const bundle = { schemaVersion: 1, target: { ...destination }, files };
  const result = await validateBundle(bundle, configured);
  if (!result.ok) throw failure(`Bundle validation failed: ${result.errors.join('; ')}`);
  return bundle;
}

function assertSha(value, label) {
  if (typeof value !== 'string' || !SHA.test(value)) throw failure(`GitHub returned an invalid ${label}.`);
  return value.toLowerCase();
}

/** Push one additive tree/commit with a checked parent and a nonforced reference update. */
export async function pushBundle(bundle, { token, expectedHead, policies, fetchImpl = globalThis.fetch } = {}) {
  const result = await validateBundle(bundle, policies);
  if (!result.ok) throw failure(`Bundle validation failed: ${result.errors.join('; ')}`);
  if (typeof token !== 'string' || !token.trim() || /[\r\n]/u.test(token)) throw failure('Set GH_TOKEN or GITHUB_TOKEN before pushing.');
  if (typeof expectedHead !== 'string' || !SHA.test(expectedHead)) throw failure('--expected-head must be a full 40-character commit SHA.');
  const expected = expectedHead.toLowerCase();
  const { owner, repository, branch } = bundle.target;
  const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}`;
  const branchPath = branch.split('/').map(encodeURIComponent).join('/');
  const refPath = `/git/ref/heads/${branchPath}`;
  const headers = {
    Accept: 'application/vnd.github+json', Authorization: `Bearer ${token.trim()}`,
    'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28',
  };
  async function request(method, resource, body) {
    let response;
    try {
      response = await fetchImpl(`${base}${resource}`, {
        method, headers, redirect: 'error', signal: AbortSignal.timeout(30_000),
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      throw failure(`GitHub ${method} request failed; check network access and retry with a fresh expected head.`);
    }
    if (!response.ok) {
      const status = Number.isInteger(response.status) ? response.status : 'unknown';
      throw failure(`GitHub ${method} request failed (HTTP ${status}); no forced reference update was attempted.`);
    }
    try {
      return await response.json();
    } catch {
      throw failure('GitHub returned an invalid JSON response.');
    }
  }
  async function currentHead() {
    const ref = await request('GET', refPath);
    return assertSha(ref?.object?.sha, 'branch head');
  }
  if (await currentHead() !== expected) throw failure('The remote branch head differs from --expected-head; refresh the bundle and expected head.');
  const parent = await request('GET', `/git/commits/${expected}`);
  const baseTree = assertSha(parent?.tree?.sha, 'base tree SHA');
  const tree = await request('POST', '/git/trees', {
    base_tree: baseTree,
    tree: bundle.files.map(({ path: filePath, mode, content }) => ({ path: filePath, mode, type: 'blob', content })),
  });
  const treeSha = assertSha(tree?.sha, 'tree SHA');
  const commit = await request('POST', '/git/commits', {
    message: 'chore: synchronize Dune-Sub ecosystem source files', tree: treeSha, parents: [expected],
  });
  const commitSha = assertSha(commit?.sha, 'commit SHA');
  if (await currentHead() !== expected) throw failure('The remote branch changed during synchronization; the new commit was not attached to the branch.');
  const updated = await request('PATCH', `/git/refs/heads/${branchPath}`, { sha: commitSha, force: false });
  if (assertSha(updated?.object?.sha, 'updated branch head') !== commitSha) throw failure('GitHub did not confirm the requested branch update; inspect the remote branch before retrying.');
  return { owner, repository, branch, commitSha, treeSha, url: `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/commit/${commitSha}` };
}

/** Write atomically; reject existing symlink paths so generated output never follows them. */
export async function writeBundle(outputPath, bundle) {
  const output = path.resolve(outputPath);
  async function checkAncestors() {
    let cursor = output;
    for (;;) {
      try {
        if ((await fs.lstat(cursor)).isSymbolicLink()) throw failure('The bundle output path cannot contain symlinks.');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      const parent = path.dirname(cursor);
      if (parent === cursor) break;
      cursor = parent;
    }
  }
  await checkAncestors();
  await fs.mkdir(path.dirname(output), { recursive: true });
  await checkAncestors();
  const temporary = `${output}.${process.pid}.${createHash('sha256').update(String(Math.random())).digest('hex').slice(0, 12)}.tmp`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(bundle, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await fs.rename(temporary, output);
  } finally {
    await fs.rm(temporary, { force: true });
  }
  return output;
}
