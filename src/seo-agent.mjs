#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSeoAgentClient } from './lib/seo-agent.mjs';

const DEFAULT_CONFIG = fileURLToPath(new URL('../config/seo-agent.json', import.meta.url));
const COMMANDS = new Set(['status', 'findings', 'proposals', 'changes', 'overrides', 'analytics', 'run', 'approve', 'reject', 'revert']);
const DECISIONS = new Set(['approve', 'reject', 'revert']);
const HELP = `Usage: ecosystem-seo [command] [options]

Connect Ecosystem to a separately deployed seo-agent Cloudflare Worker.
The default command is status. Results are printed as JSON.

Read commands:
  status                Latest crawl, findings, and Worker configuration
  findings              Findings (default status: open)
  proposals             Proposals (default status: proposed)
  changes               Change journal
  overrides             Current KV overrides
  analytics             SEO/AEO analytics summary

Explicit actions:
  run                   Start a background crawl; poll status for completion
  approve --id NUMBER   Approve and apply a proposal to the site's KV overrides
  reject --id NUMBER    Reject a proposal
  revert --id NUMBER    Revert a change from the journal

Options:
  --config PATH         JSON configuration (default: repository config/seo-agent.json)
  --status STATUS       Filter findings or proposals only
  --id NUMBER           Positive proposal/change ID; required for decisions
  --help                Show this help without connecting

Set SEO_AGENT_URL to the Worker's HTTPS origin (overrides config.url).
Set SEO_AGENT_TOKEN in your environment to the Worker's AGENT_TOKEN.
Tokens are never read from config or command-line arguments.
See docs/seo-agent.md for Worker deployment and injector setup.
`;

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--help' || argument === '-h') {
      if (args.length !== 1) throw new Error('Use --help without other arguments.');
      return { help: true };
    }
    if (!argument.startsWith('-')) {
      if (options.command || !COMMANDS.has(argument)) throw new Error('Supply one supported command; use --help.');
      options.command = argument;
      continue;
    }
    const name = argument.slice(2);
    if (!['config', 'status', 'id'].includes(name)) throw new Error('Unknown option; use --help.');
    if (Object.hasOwn(options, name)) throw new Error('Duplicate option; use --help.');
    const value = args[++index];
    if (!value || value.startsWith('-')) throw new Error('Option requires a value; use --help.');
    options[name] = value;
  }
  options.command ??= 'status';
  if (options.status !== undefined && !['findings', 'proposals'].includes(options.command)) {
    throw new Error('--status is supported only with findings or proposals.');
  }
  if (DECISIONS.has(options.command)) {
    if (!options.id || !/^[1-9]\d*$/.test(options.id) || !Number.isSafeInteger(Number(options.id))) {
      throw new Error('This command requires --id with a positive safe integer.');
    }
    options.id = Number(options.id);
  } else if (options.id !== undefined) {
    throw new Error('--id is supported only with approve, reject, or revert.');
  }
  return options;
}

async function readConfiguration(filename) {
  let config;
  try {
    config = JSON.parse(await readFile(filename, 'utf8'));
  } catch {
    throw new Error('Cannot read SEO agent configuration as JSON; check --config.');
  }
  if (!config || typeof config !== 'object' || Array.isArray(config)
    || Object.keys(config).sort().join(',') !== 'timeoutMs,url,version'
    || config.version !== 1 || typeof config.url !== 'string'
    || !Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 120000) {
    throw new Error('SEO agent configuration requires version 1, url, and timeoutMs (1–120000); no other fields are allowed.');
  }
  return config;
}

/** Injectable transport and streams keep CLI checks independent of a deployed Worker. */
export async function runCli(args, { env = process.env, cwd = process.cwd(), stdout = process.stdout, stderr = process.stderr, fetchImpl = globalThis.fetch } = {}) {
  const token = typeof env.SEO_AGENT_TOKEN === 'string' ? env.SEO_AGENT_TOKEN : '';
  const tokens = [...new Set([token, token.trim()].filter(Boolean)
    .flatMap(value => [value, JSON.stringify(value).slice(1, -1)]))]
    .sort((left, right) => right.length - left.length);
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
    const config = await readConfiguration(options.config ? path.resolve(cwd, options.config) : DEFAULT_CONFIG);
    const client = createSeoAgentClient({
      url: env.SEO_AGENT_URL ?? config.url,
      token: env.SEO_AGENT_TOKEN,
      timeoutMs: config.timeoutMs,
      fetchImpl,
    });
    let result;
    if (DECISIONS.has(options.command)) result = await client[options.command](options.id);
    else if (['findings', 'proposals'].includes(options.command)) result = await client[options.command](options.status);
    else result = await client[options.command]();
    write(stdout, `${JSON.stringify(result, null, 2)}\n`);
    return 0;
  } catch (error) {
    write(stderr, `ecosystem-seo: ${error instanceof Error ? error.message : 'SEO agent request failed.'}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCli(process.argv.slice(2));
}
