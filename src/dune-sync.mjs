#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPolicies } from './lib/validation.mjs';
import { createBundle, pushBundle, writeBundle } from './lib/sync.mjs';

const HELP = `Usage: dune-sync [options]

Creates and validates a deterministic UTF-8 bundle of Git tracked and untracked,
nonignored repository files. The default operation writes a local bundle.

  --root DIRECTORY      Repository root (default: current directory)
  --org OWNER           Must match the configured destination owner
  --repo REPOSITORY     Must match the configured destination repository
  --branch BRANCH       Must match the configured destination branch
  --output PATH         Bundle path, relative to root (default: dist/ecosystem-sync.json)
  --snapshot            Walk a provided source tar without Git (e.g. Cloud Build)
  --push                Push an additive GitHub commit without forcing the branch
  --expected-head SHA   Required with --push; current full remote commit SHA
  --help                Show this help

Destination and limits: config/gateway-policies.json.
Push authentication: GH_TOKEN or GITHUB_TOKEN (never included in the bundle).
`;

function parseOptions(args) {
  const options = {};
  const valued = new Set(['root', 'org', 'repo', 'branch', 'output', 'expected-head']);
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (!argument.startsWith('--')) throw new Error('Only named options are supported; use --help.');
    const name = argument.slice(2);
    if (Object.hasOwn(options, name)) throw new Error(`Duplicate option --${name}.`);
    if (name === 'help' || name === 'push' || name === 'snapshot') {
      options[name] = true;
    } else if (valued.has(name)) {
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new Error(`Option --${name} requires a value.`);
      options[name] = value;
    } else {
      throw new Error('Unknown option; use --help.');
    }
  }
  return options;
}

/** Exported for direct CLI tests; defaults use the real environment and GitHub transport. */
export async function runCli(args, { env = process.env, cwd = process.cwd(), stdout = process.stdout, stderr = process.stderr, fetchImpl = globalThis.fetch } = {}) {
  const tokens = [...new Set([env.GH_TOKEN, env.GITHUB_TOKEN]
    .filter((value) => typeof value === 'string' && value.length)
    .flatMap((value) => [value, value.trim()]).filter(Boolean))].sort((left, right) => right.length - left.length);
  const write = (stream, message) => {
    let safe = message;
    for (const token of tokens) safe = safe.split(token).join('[REDACTED]');
    stream.write(safe);
  };
  try {
    const options = parseOptions(args);
    if (options.help) {
      write(stdout, HELP);
      return 0;
    }
    if (options.push && (!options['expected-head'] || !/^[a-f0-9]{40}$/i.test(options['expected-head']))) {
      throw new Error('--expected-head must be a full 40-character commit SHA when using --push.');
    }
    if (options.push && !env.GH_TOKEN && !env.GITHUB_TOKEN) throw new Error('Set GH_TOKEN or GITHUB_TOKEN before pushing.');
    const rootDir = path.resolve(cwd, options.root ?? '.');
    const policies = await loadPolicies(rootDir);
    const target = {
      owner: options.org ?? policies.target.owner,
      repository: options.repo ?? policies.target.repository,
      branch: options.branch ?? policies.target.branch,
    };
    const output = path.resolve(rootDir, options.output ?? 'dist/ecosystem-sync.json');
    const relativeOutput = path.relative(rootDir, output).split(path.sep).join('/');
    const excludePaths = relativeOutput && !relativeOutput.startsWith('../') ? [relativeOutput] : [];
    const bundle = await createBundle(rootDir, { policies, target, excludePaths, snapshot: options.snapshot ?? false });
    await writeBundle(output, bundle);
    write(stdout, `Wrote ${bundle.files.length} verified files to ${output}\n`);
    if (options.push) {
      const receipt = await pushBundle(bundle, { token: env.GH_TOKEN || env.GITHUB_TOKEN, expectedHead: options['expected-head'], policies, fetchImpl });
      write(stdout, `Pushed ${receipt.commitSha} to ${receipt.owner}/${receipt.repository}/${receipt.branch}\n${receipt.url}\n`);
    }
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Synchronization failed.';
    write(stderr, `dune-sync: ${message}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCli(process.argv.slice(2));
}
