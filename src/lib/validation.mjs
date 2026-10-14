import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { findCredentialFindings } from './security-scan.mjs';

const POLICY_PATH = 'config/gateway-policies.json';
const MANIFEST_PATH = 'docs/source_manifest.json';
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => isObject(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const sha256 = data => createHash('sha256').update(data).digest('hex');

export function safeRelativePath(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 &&
    !/[\\\x00-\x1f\x7f:]/.test(value) && !path.posix.isAbsolute(value) &&
    value.split('/').every(part => part !== '' && part !== '.' && part !== '..' && part !== '.git');
}

function validBranch(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 255 &&
    !/[\x00-\x20\x7f~^:?*\[\\]/.test(value) && !value.includes('..') && !value.includes('@{') &&
    value !== '@' && !value.startsWith('/') && !value.endsWith('/') && !value.endsWith('.') &&
    value.split('/').every(part => part && !part.startsWith('.') && !part.endsWith('.lock'));
}

function validTarget(value) {
  return exactKeys(value, ['owner', 'repository', 'branch']) &&
    typeof value.owner === 'string' && typeof value.repository === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(value.owner) &&
    /^[A-Za-z0-9_.-]{1,100}$/.test(value.repository) && !['.', '..'].includes(value.repository) &&
    validBranch(value.branch);
}

export function validatePolicies(policies) {
  const errors = [];
  if (!exactKeys(policies, ['schemaVersion', 'target', 'integrity', 'limits']) || policies.schemaVersion !== 1) {
    return { ok: false, errors: ['Policy must contain schemaVersion 1, target, integrity, and limits.'] };
  }
  if (!validTarget(policies.target)) errors.push('Policy target is invalid.');
  if (!exactKeys(policies.integrity, ['algorithm', 'rejectSymlinks']) ||
      policies.integrity.algorithm !== 'sha256' || policies.integrity.rejectSymlinks !== true) {
    errors.push('Policy must require SHA-256 integrity and reject symlinks.');
  }
  if (!exactKeys(policies.limits, ['maxFiles', 'maxFileBytes', 'maxTotalBytes'])) {
    errors.push('Policy limits are invalid.');
  } else {
    for (const [key, maximum] of [['maxFiles', 10000], ['maxFileBytes', 10485760], ['maxTotalBytes', 52428800]]) {
      const value = policies.limits[key];
      if (!Number.isSafeInteger(value) || value < 1 || value > maximum) errors.push(`Policy limit ${key} is out of range.`);
    }
    if (policies.limits.maxFileBytes > policies.limits.maxTotalBytes) errors.push('Per-file limit exceeds total byte limit.');
  }
  return { ok: errors.length === 0, errors };
}

export async function readRepositoryFile(rootDir, relativePath, maxBytes = 1048576) {
  if (!safeRelativePath(relativePath)) throw new Error('Unsafe repository path.');
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error('Invalid file byte limit.');
  const root = await realpath(rootDir);
  if (root !== path.resolve(rootDir)) throw new Error('Symlinked repository roots are not allowed.');
  let location = root;
  for (const part of relativePath.split('/')) {
    location = path.join(location, part);
    const stat = await lstat(location);
    if (stat.isSymbolicLink()) throw new Error('Symlink paths are not allowed.');
  }
  const stat = await lstat(location);
  if (!stat.isFile()) throw new Error('Repository path is not a regular file.');
  const actual = await realpath(location);
  const relative = path.relative(root, actual);
  if (relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) throw new Error('Path escapes repository root.');
  const handle = await open(actual, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.dev !== stat.dev || before.ino !== stat.ino || await realpath(location) !== actual) {
      throw new Error('Repository file changed or is not a regular file.');
    }
    if (before.size > maxBytes) throw new Error('File exceeds byte limit.');
    const buffer = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (offset > maxBytes || after.size > maxBytes) throw new Error('File exceeds byte limit.');
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || offset !== after.size) {
      throw new Error('Repository file changed during validation.');
    }
    return buffer.subarray(0, offset);
  } finally {
    await handle.close();
  }
}

async function readJson(rootDir, relativePath) {
  const bytes = await readRepositoryFile(rootDir, relativePath);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`Invalid UTF-8 JSON in ${relativePath}.`);
  }
}

export async function loadPolicies(rootDir) {
  const policies = await readJson(rootDir, POLICY_PATH);
  const result = validatePolicies(policies);
  if (!result.ok) throw new Error(result.errors.join(' '));
  return policies;
}

export async function validateRepository(rootDir = process.cwd()) {
  const errors = [];
  let policies;
  let manifest;
  try { policies = await loadPolicies(rootDir); }
  catch (error) { errors.push(`Policy validation failed: ${error.code || error.message}`); }
  try { manifest = await readJson(rootDir, MANIFEST_PATH); }
  catch (error) { errors.push(`Source manifest validation failed: ${error.code || error.message}`); }
  if (errors.length) return { ok: false, errors, filesChecked: 0 };
  if (!isObject(manifest) || manifest.schema_version !== 1 || !Array.isArray(manifest.documents) || !Array.isArray(manifest.source_files)) {
    return { ok: false, errors: ['Source manifest must contain schema_version 1, documents, and source_files arrays.'], filesChecked: 0 };
  }
  const entries = [...manifest.documents, ...manifest.source_files];
  if (entries.length > policies.limits.maxFiles) return { ok: false, errors: ['Source manifest exceeds the policy file limit.'], filesChecked: 0 };
  const seen = new Set();
  let total = 0;
  let filesChecked = 0;
  for (const entry of entries) {
    if (!isObject(entry) || !safeRelativePath(entry.path) || entry.path === MANIFEST_PATH) {
      errors.push('Source manifest contains an unsafe or self-referential path.');
      continue;
    }
    if (seen.has(entry.path)) { errors.push(`Duplicate source manifest path: ${entry.path}`); continue; }
    seen.add(entry.path);
    if (!Number.isSafeInteger(entry.size_bytes) || entry.size_bytes < 0 ||
        typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
      errors.push(`Invalid integrity metadata: ${entry.path}`);
      continue;
    }
    try {
      const data = await readRepositoryFile(rootDir, entry.path, policies.limits.maxFileBytes);
      total += data.length;
      if (data.length > policies.limits.maxFileBytes) errors.push(`File exceeds byte limit: ${entry.path}`);
      if (data.length !== entry.size_bytes) errors.push(`Byte count mismatch: ${entry.path}`);
      if (sha256(data) !== entry.sha256) errors.push(`SHA-256 mismatch: ${entry.path}`);
      filesChecked++;
    } catch (error) {
      errors.push(`Unreadable source artifact: ${entry.path} (${error.code || error.message})`);
    }
  }
  if (total > policies.limits.maxTotalBytes) errors.push('Source artifacts exceed the total byte limit.');
  return { ok: errors.length === 0, errors, filesChecked };
}

export function validateBundle(bundle, policies) {
  const errors = [];
  const limits = policies?.limits || { maxFiles: 2000, maxFileBytes: 1048576, maxTotalBytes: 5242880 };
  if (policies) {
    const result = validatePolicies(policies);
    if (!result.ok) return result;
  }
  if (!exactKeys(bundle, ['schemaVersion', 'target', 'files']) || bundle.schemaVersion !== 1 || !validTarget(bundle.target) || !Array.isArray(bundle.files)) {
    return { ok: false, errors: ['Bundle must contain schemaVersion 1, a valid target, and files.'] };
  }
  if (policies && ['owner', 'repository', 'branch'].some(key => bundle.target[key] !== policies.target[key])) {
    errors.push('Bundle target does not match the configured policy.');
  }
  if (bundle.files.length < 1 || bundle.files.length > limits.maxFiles) errors.push('Bundle file count is outside policy limits.');
  const seen = new Set();
  let total = 0;
  for (const file of bundle.files) {
    if (!exactKeys(file, ['path', 'mode', 'content', 'sha256', 'bytes']) || !safeRelativePath(file.path)) {
      errors.push('Bundle contains an invalid file entry or unsafe path.');
      continue;
    }
    if (seen.has(file.path)) errors.push(`Duplicate bundle path: ${file.path}`);
    seen.add(file.path);
    const basename = path.posix.basename(file.path);
    if ((basename === '.env' || basename.startsWith('.env.')) && basename !== '.env.example') errors.push('Environment secret files cannot be synchronized.');
    if (file.mode !== '100644') errors.push(`Unsupported file mode: ${file.path}`);
    if (typeof file.content !== 'string' || !Number.isSafeInteger(file.bytes) || file.bytes < 0 ||
        typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256)) {
      errors.push(`Invalid bundle integrity metadata: ${file.path}`);
      continue;
    }
    const data = Buffer.from(file.content, 'utf8');
    for (const finding of findCredentialFindings(file.content, file.path)) {
      errors.push(`Credential pattern in bundle: ${finding.path}:${finding.line} (${finding.rule})`);
    }
    total += data.length;
    if (new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data) !== file.content) errors.push(`Noncanonical UTF-8 content: ${file.path}`);
    if (data.length !== file.bytes) errors.push(`Bundle byte count mismatch: ${file.path}`);
    if (sha256(data) !== file.sha256) errors.push(`Bundle SHA-256 mismatch: ${file.path}`);
    if (data.length > limits.maxFileBytes) errors.push(`Bundle file exceeds byte limit: ${file.path}`);
  }
  if (total > limits.maxTotalBytes) errors.push('Bundle exceeds total byte limit.');
  const embeddedManifest = bundle.files.find(file => file?.path === MANIFEST_PATH);
  if (embeddedManifest && typeof embeddedManifest.content === 'string') {
    let manifest;
    try { manifest = JSON.parse(embeddedManifest.content); }
    catch { errors.push('Embedded source manifest is invalid JSON.'); }
    if (manifest !== undefined) {
      if (!isObject(manifest) || manifest.schema_version !== 1 || !Array.isArray(manifest.documents) || !Array.isArray(manifest.source_files)) {
        errors.push('Embedded source manifest has an invalid structure.');
      } else {
        const artifacts = [...manifest.documents, ...manifest.source_files];
        const files = new Map(bundle.files.filter(file => isObject(file)).map(file => [file.path, file]));
        const paths = new Set();
        if (artifacts.length > limits.maxFiles) errors.push('Embedded source manifest exceeds file limit.');
        for (const artifact of artifacts) {
          if (!isObject(artifact) || !safeRelativePath(artifact.path) || artifact.path === MANIFEST_PATH || paths.has(artifact.path)) {
            errors.push('Embedded source manifest contains an unsafe, duplicate, or self-referential path.');
            continue;
          }
          paths.add(artifact.path);
          const file = files.get(artifact.path);
          if (!Number.isSafeInteger(artifact.size_bytes) || artifact.size_bytes < 0 ||
              typeof artifact.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifact.sha256) ||
              !file || artifact.size_bytes !== file.bytes || artifact.sha256 !== file.sha256) {
            errors.push(`Embedded source artifact integrity mismatch: ${artifact.path}`);
          }
        }
      }
    }
  }
  return { ok: errors.length === 0, errors };
}
