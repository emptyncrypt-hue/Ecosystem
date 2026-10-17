import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../services/seo-agent/', import.meta.url));
const manifest = JSON.parse(await readFile(path.join(root, 'UPSTREAM.json'), 'utf8'));
const sha256 = /^[a-f0-9]{64}$/;
if (manifest.schemaVersion !== 1 || !/^[a-f0-9]{40}$/.test(manifest.commit)
    || manifest.hashAlgorithm !== 'SHA-256' || manifest.license !== 'MIT'
    || !manifest.files || !manifest.originalFiles || !Array.isArray(manifest.patchedPaths)) {
  throw new Error('Invalid SEO service provenance metadata.');
}
for (const [name, digest] of Object.entries(manifest.files)) {
  const parts = name.split('/');
  if (!name || path.posix.isAbsolute(name) || name.includes('\\')
      || parts.some(part => !part || ['.', '..', '.git', 'node_modules', '.wrangler'].includes(part))
      || !sha256.test(digest)) throw new Error('Unsafe SEO service provenance entry.');
  let candidate = root;
  for (const part of parts) {
    candidate = path.join(candidate, part);
    if ((await lstat(candidate)).isSymbolicLink()) throw new Error('SEO service source cannot use symlinks.');
  }
  const stat = await lstat(candidate);
  if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error('Invalid SEO service source file.');
  const actual = createHash('sha256').update(await readFile(candidate)).digest('hex');
  if (actual !== digest) throw new Error(`SEO service provenance mismatch: ${name}`);
}
for (const [name, digest] of Object.entries(manifest.originalFiles)) {
  if (!sha256.test(digest) || !Object.hasOwn(manifest.files, name)) throw new Error('Incomplete SEO upstream provenance.');
  if (manifest.files[name] !== digest && !manifest.patchedPaths.includes(name)) {
    throw new Error(`Undocumented SEO upstream modification: ${name}`);
  }
}
console.log(`Verified ${Object.keys(manifest.files).length} SEO service files against pinned source provenance.`);
