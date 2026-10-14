#!/usr/bin/env node
import { scanRepository, SecurityScanError } from './lib/security-scan.mjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HELP = `Usage: security-scan [--root directory] [--target owner] [--policy dune-sub-baseline]

Scan current repository text files for common credential patterns and sensitive .env files.
The default target comes from config/security-policy.json. Findings contain path, line, and
rule only. Git history and the excluded .git, node_modules, dist, generated, .terraform,
and __pycache__ directories
are outside this limited baseline; passing does not certify overall security.

Exit status: 0 clean baseline, 1 findings or unsafe/unreadable inputs, 2 invalid arguments/policy.
`;

function parseArguments(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--help' || argument === '-h') {
      if (args.length !== 1) throw new SecurityScanError('Help must be requested without other arguments.');
      return { help: true };
    }
    const equals = argument.indexOf('=');
    const flag = equals < 0 ? argument : argument.slice(0, equals);
    const names = { '--root': 'root', '--target': 'target', '--policy': 'policy' };
    if (!Object.hasOwn(names, flag)) throw new SecurityScanError('Unknown argument.');
    const name = names[flag];
    if (Object.hasOwn(options, name)) throw new SecurityScanError('Duplicate argument.');
    const value = equals < 0 ? args[++index] : argument.slice(equals + 1);
    if (!value || value.startsWith('--')) throw new SecurityScanError('Argument value is required.');
    options[name] = value;
  }
  return options;
}

export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  try {
    const options = parseArguments(args);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    const result = await scanRepository(options);
    stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.ok ? 0 : 1;
  } catch (error) {
    stderr.write(`security-scan: ${error instanceof SecurityScanError ? error.message : 'Scan failed.'}\n`);
    return 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
