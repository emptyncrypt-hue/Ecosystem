#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { loadPolicies, validateBundle, validateRepository } from './lib/validation.mjs';

async function main() {
  const args = process.argv.slice(2);
  let root = process.cwd();
  let bundle;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help') { console.log('Usage: validate-payload [--root directory] [--bundle file]'); return; }
    if (!['--root', '--bundle'].includes(args[i]) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Unknown option or missing argument.');
    const flag = args[i++];
    if (flag === '--root') root = args[i]; else bundle = args[i];
  }
  const result = bundle
    ? validateBundle(JSON.parse(await readFile(bundle, 'utf8')), await loadPolicies(root))
    : await validateRepository(root);
  if (!result.ok) {
    for (const error of result.errors) console.error(error);
    process.exitCode = 1;
    return;
  }
  console.log(JSON.stringify({ ok: true, ...(result.filesChecked !== undefined ? { filesChecked: result.filesChecked } : {}) }));
}

main().catch(error => {
  console.error(error instanceof SyntaxError ? 'Invalid bundle JSON.' : error.message);
  process.exitCode = 1;
});
