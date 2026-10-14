import { constants } from 'node:fs';
import { lstat, open, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { isUtf8 } from 'node:buffer';
import { fileURLToPath } from 'node:url';

const BASELINE_NAME = 'dune-sub-baseline';
const EXCLUDED_DIRECTORIES = ['.git', 'node_modules', 'dist', 'generated', '.terraform', '__pycache__'];
const DEFAULT_POLICY_PATH = fileURLToPath(new URL('../../config/security-policy.json', import.meta.url));
const CREDENTIAL_RULES = [
  ['github-token', /(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/g],
  ['github-fine-grained-token', /(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}(?![A-Za-z0-9_])/g],
  ['openai-api-token', /(?<![A-Za-z0-9_-])sk-(?:(?:proj|svcacct)-[A-Za-z0-9_-]{40,240}|[A-Za-z0-9]{48})(?![A-Za-z0-9_-])/g],
  ['aws-access-key-id', /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/g],
  ['pem-private-key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g],
];

export class SecurityScanError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SecurityScanError';
  }
}

export async function loadSecurityPolicy(policyPath = DEFAULT_POLICY_PATH, requestedPolicy = BASELINE_NAME) {
  if (requestedPolicy !== BASELINE_NAME) throw new SecurityScanError('Unknown security policy.');
  let policy;
  try {
    policy = JSON.parse(await readFile(policyPath, 'utf8'));
  } catch {
    throw new SecurityScanError('Security policy cannot be read as JSON.');
  }
  const keys = ['version', 'name', 'target', 'maxFileBytes', 'excludedDirectories'];
  if (!policy || Array.isArray(policy) || typeof policy !== 'object'
    || Object.keys(policy).sort().join(',') !== keys.sort().join(',')
    || policy.version !== 1 || policy.name !== BASELINE_NAME
    || typeof policy.target !== 'string' || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(policy.target)
    || !Number.isSafeInteger(policy.maxFileBytes) || policy.maxFileBytes < 1 || policy.maxFileBytes > 16 * 1024 * 1024
    || !Array.isArray(policy.excludedDirectories)
    || policy.excludedDirectories.length !== EXCLUDED_DIRECTORIES.length
    || [...policy.excludedDirectories].sort().join(',') !== [...EXCLUDED_DIRECTORIES].sort().join(',')) {
    throw new SecurityScanError('Security policy has an invalid baseline configuration.');
  }
  return Object.freeze({ ...policy, excludedDirectories: Object.freeze([...policy.excludedDirectories]) });
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function withinRoot(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}

function compareFindings(left, right) {
  const first = `${left.path}\0${String(left.line).padStart(12, '0')}\0${left.rule}`;
  const second = `${right.path}\0${String(right.line).padStart(12, '0')}\0${right.rule}`;
  return first < second ? -1 : first > second ? 1 : 0;
}

/** Return only locations and rule names; credential values never leave this matcher. */
export function findCredentialFindings(text, relativePath) {
  const findings = [];
  for (const [rule, expression] of CREDENTIAL_RULES) {
    const matcher = new RegExp(expression.source, expression.flags);
    let lastOffset = 0;
    let line = 1;
    for (const match of text.matchAll(matcher)) {
      for (let index = lastOffset; index < match.index; index += 1) if (text[index] === '\n') line += 1;
      lastOffset = match.index;
      findings.push({ path: relativePath, line, rule });
    }
  }
  const unique = new Map(findings.map(finding => [`${finding.path}\0${finding.line}\0${finding.rule}`, finding]));
  return [...unique.values()].sort(compareFindings);
}

function textFromBuffer(buffer) {
  // Support BOM-marked UTF-16 source files; do not treat arbitrary binaries as text.
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString('utf16le');
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const swapped = Buffer.from(buffer.subarray(2));
    if (swapped.length % 2) return null;
    return swapped.swap16().toString('utf16le');
  }
  if (buffer.includes(0) || !isUtf8(buffer)) return null;
  return buffer.toString('utf8');
}

/** Scan current working-tree files, including ignored files. Git history is outside this baseline. */
export async function scanRepository({ root = process.cwd(), target, policy = BASELINE_NAME, policyPath } = {}) {
  const configuration = await loadSecurityPolicy(policyPath, policy);
  const selectedTarget = target ?? configuration.target;
  if (selectedTarget !== configuration.target) throw new SecurityScanError('Target does not match the configured security policy.');
  if (typeof root !== 'string' || root.length === 0) throw new SecurityScanError('Root must be a directory path.');
  const rootPath = path.resolve(root);
  const result = {
    ok: false,
    policy: configuration.name,
    target: selectedTarget,
    scannedFiles: 0,
    skippedBinaryFiles: 0,
    findings: [],
    errors: [],
  };
  const addError = (relativePath, rule) => result.errors.push({ path: relativePath || '.', line: 1, rule });
  const addFinding = (relativePath, line, rule) => result.findings.push({ path: relativePath, line, rule });

  async function inspectFile(absolutePath, relativePath, expected) {
    if (/^\.env(?:\..+)?$/.test(path.basename(absolutePath)) && path.basename(absolutePath) !== '.env.example') {
      addFinding(relativePath, 1, 'sensitive-env-file');
    }
    if (expected.size > configuration.maxFileBytes) {
      addError(relativePath, 'file-size-limit');
      return;
    }
    let handle;
    try {
      if (!withinRoot(rootPath, absolutePath) || await realpath(absolutePath) !== absolutePath) {
        addError(relativePath, 'unsafe-path');
        return;
      }
      handle = await open(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const opened = await handle.stat();
      if (!opened.isFile() || !sameFile(expected, opened) || await realpath(absolutePath) !== absolutePath) {
        addError(relativePath, 'file-changed-during-scan');
        return;
      }
      // Read a bounded amount even if another process grows the file after the stat.
      const buffer = Buffer.alloc(Math.min(opened.size, configuration.maxFileBytes) + 1);
      let offset = 0;
      while (offset < buffer.length) {
        const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
        if (!bytesRead) break;
        offset += bytesRead;
      }
      const finalStat = await handle.stat();
      if (offset > configuration.maxFileBytes || finalStat.size > configuration.maxFileBytes) {
        addError(relativePath, 'file-size-limit');
        return;
      }
      if (finalStat.size !== opened.size || finalStat.mtimeMs !== opened.mtimeMs || offset !== opened.size) {
        addError(relativePath, 'file-changed-during-scan');
        return;
      }
      const text = textFromBuffer(buffer.subarray(0, offset));
      if (text === null) {
        result.skippedBinaryFiles += 1;
        return;
      }
      result.scannedFiles += 1;
      result.findings.push(...findCredentialFindings(text, relativePath));
    } catch {
      addError(relativePath, 'unreadable-or-unsafe-file');
    } finally {
      if (handle) await handle.close();
    }
  }

  async function walk(directory, relativeDirectory, expected) {
    try {
      const current = await lstat(directory);
      if (current.isSymbolicLink() || !current.isDirectory() || !sameFile(expected, current)
        || !withinRoot(rootPath, directory) || await realpath(directory) !== directory) {
        addError(relativeDirectory, 'unsafe-directory');
        return;
      }
      const entries = (await readdir(directory)).sort();
      for (const name of entries) {
        // Git worktrees can use a .git pointer file; neither it nor Git internals are source inputs.
        if (name === '.git') continue;
        const absolutePath = path.join(directory, name);
        const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name;
        let entry;
        try {
          entry = await lstat(absolutePath);
        } catch {
          addError(relativePath, 'unreadable-or-unsafe-file');
          continue;
        }
        if (entry.isSymbolicLink()) addError(relativePath, 'symlink');
        else if (entry.isDirectory()) {
          if (!configuration.excludedDirectories.includes(name)) await walk(absolutePath, relativePath, entry);
        } else if (entry.isFile()) await inspectFile(absolutePath, relativePath, entry);
        else addError(relativePath, 'unsupported-file-type');
      }
    } catch {
      addError(relativeDirectory, 'unreadable-or-unsafe-directory');
    }
  }

  try {
    const rootStat = await lstat(rootPath);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory() || await realpath(rootPath) !== rootPath) addError('.', 'unsafe-root');
    else await walk(rootPath, '', rootStat);
  } catch {
    addError('.', 'unreadable-root');
  }
  const uniqueFindings = new Map(result.findings.map(finding => [`${finding.path}\0${finding.line}\0${finding.rule}`, finding]));
  result.findings = [...uniqueFindings.values()].sort(compareFindings);
  result.errors.sort(compareFindings);
  result.ok = result.findings.length === 0 && result.errors.length === 0;
  return result;
}
