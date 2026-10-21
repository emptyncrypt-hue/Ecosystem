import { randomBytes, webcrypto } from 'node:crypto';
import { isIP } from 'node:net';

const encoder = new TextEncoder();
const MAX_PLAINTEXT_BYTES = 2048;
const MAX_ENVELOPE_BYTES = 4096;
const SOFTWARE_SECRET_NAMES = ['INTERNAL_LLMS_KEY', 'INTERNAL_LLMS_CIPHERTEXT'];
const BRIDGE_SECRET_NAMES = ['INTERNAL_LLMS_BRIDGE_URL', 'INTERNAL_LLMS_BRIDGE_TOKEN', 'INTERNAL_LLMS_BRIDGE_KEY_ID'];
export const INTERNAL_LLMS_SECRET_NAMES = Object.freeze(['INTERNAL_LLMS_PROVIDER', ...SOFTWARE_SECRET_NAMES, ...BRIDGE_SECRET_NAMES]);

function context(siteUrl) {
  let site;
  try { site = new URL(siteUrl); } catch { /* Validated below. */ }
  if (!site || site.protocol !== 'https:' || site.username || site.password
      || site.pathname !== '/' || site.search || site.hash) {
    throw new Error('Internal LLM document requires an HTTPS site origin without credentials, path, query, or fragment.');
  }
  return encoder.encode(`dunesub-internal-llms:v1\n${site.origin}\n/internal/llms.txt`);
}

function decode(value, minimum, maximum) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(maximum * 4 / 3)) throw new Error('Invalid internal LLM encryption encoding.');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString('base64url') !== value) {
    throw new Error('Invalid internal LLM encryption encoding.');
  }
  return bytes;
}

function validatePlaintext(bytes) {
  if (bytes.length < 1 || bytes.length > MAX_PLAINTEXT_BYTES) {
    throw new Error('Internal LLM document must contain 1–2048 UTF-8 bytes.');
  }
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new Error('Internal LLM document must be valid UTF-8 text.'); }
  if (text.includes('\0')) throw new Error('Internal LLM document must not contain NUL bytes.');
}

function parseEnvelope(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_ENVELOPE_BYTES) {
    throw new Error('Internal LLM encryption envelope must be a JSON string of at most 4096 UTF-8 bytes.');
  }
  let envelope;
  try { envelope = JSON.parse(value); } catch { throw new Error('Invalid internal LLM encryption envelope.'); }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
      || Object.keys(envelope).length !== 4
      || !['version', 'algorithm', 'nonce', 'ciphertext'].every(key => Object.hasOwn(envelope, key))
      || envelope.version !== 1 || envelope.algorithm !== 'AES-256-GCM') {
    throw new Error('Invalid internal LLM encryption envelope.');
  }
  return { nonce: decode(envelope.nonce, 12, 12), ciphertext: decode(envelope.ciphertext, 17, MAX_PLAINTEXT_BYTES + 16) };
}

// The caller supplies a curated document directly in memory. This module never
// reads repository files, writes artifacts, or prints plaintext or credentials.
export async function sealInternalLlms({ plaintext, siteUrl, key } = {}) {
  const additionalData = context(siteUrl);
  if (typeof plaintext !== 'string') throw new Error('Internal LLM document must be a string.');
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error('Internal LLM document must contain 1–2048 UTF-8 bytes.');
  const bytes = encoder.encode(plaintext);
  let keyBytes;
  try {
    validatePlaintext(bytes);
    if (new TextDecoder('utf-8', { ignoreBOM: true }).decode(bytes) !== plaintext) throw new Error('Internal LLM document must be valid Unicode text.');
    keyBytes = key === undefined ? randomBytes(32) : decode(key, 32, 32);
    const nonce = randomBytes(12);
    const cryptoKey = await webcrypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, cryptoKey, bytes);
    return {
      key: keyBytes.toString('base64url'),
      envelope: JSON.stringify({ version: 1, algorithm: 'AES-256-GCM', nonce: nonce.toString('base64url'), ciphertext: Buffer.from(ciphertext).toString('base64url') }),
    };
  } finally {
    bytes.fill(0);
    keyBytes?.fill(0);
  }
}

function validateBridgeSecrets(env, siteUrl) {
  context(siteUrl);
  const value = env.INTERNAL_LLMS_BRIDGE_URL;
  let bridge;
  try { if (typeof value === 'string' && value.length <= 512) bridge = new URL(value); } catch { /* Validated below. */ }
  const hostname = bridge?.hostname ?? '';
  const labels = hostname.split('.');
  if (!bridge || bridge.protocol !== 'https:' || bridge.username || bridge.password || bridge.port
      || bridge.search || bridge.hash || value !== bridge.origin + '/internal/llms.txt'
      || bridge.origin === new URL(siteUrl).origin || isIP(hostname) || labels.length < 2
      || hostname.length > 253 || /(?:^|\.)(?:localhost|local|internal)$/.test(hostname)
      || !labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error('INTERNAL_LLMS_BRIDGE_URL must be a dedicated canonical HTTPS DNS origin followed by /internal/llms.txt, without credentials, port, query, or fragment.');
  }
  const token = env.INTERNAL_LLMS_BRIDGE_TOKEN;
  let tokenBytes;
  try { tokenBytes = decode(token, 32, 32); }
  catch { throw new Error('INTERNAL_LLMS_BRIDGE_TOKEN must be a canonical base64url encoding of 32 independent random bytes.'); }
  finally { tokenBytes?.fill(0); }
  if ([env.AGENT_TOKEN, env.CLOUDFLARE_API_TOKEN, env.INTERNAL_LLMS_KEY].some(value => value !== undefined && token === value)) {
    throw new Error('INTERNAL_LLMS_BRIDGE_TOKEN must be independent of other credentials and encryption keys.');
  }
  if (typeof env.INTERNAL_LLMS_BRIDGE_KEY_ID !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(env.INTERNAL_LLMS_BRIDGE_KEY_ID)) {
    throw new Error('INTERNAL_LLMS_BRIDGE_KEY_ID must pin the attested public key as sha256 followed by 64 lowercase hexadecimal digits.');
  }
  return Object.fromEntries(['INTERNAL_LLMS_PROVIDER', ...BRIDGE_SECRET_NAMES].map(name => [name, env[name]]));
}

// Empty optional entries are absent (GitHub Actions returns empty strings for
// unconfigured secrets). Every supplied provider group must be complete. An
// absent group preserves remote bindings; selecting a mode is always explicit
// in the upload, so retained bindings from another mode cannot activate it.
export async function validateInternalLlmsSecrets({ env = {}, siteUrl } = {}) {
  const isPresent = name => env[name] !== undefined && env[name] !== '';
  if (!INTERNAL_LLMS_SECRET_NAMES.some(isPresent)) return {};
  const provider = env.INTERNAL_LLMS_PROVIDER;
  if (provider !== undefined && provider !== '' && !['software', 'yubikey-piv'].includes(provider)) {
    throw new Error('INTERNAL_LLMS_PROVIDER must be software or yubikey-piv.');
  }
  const softwarePresent = SOFTWARE_SECRET_NAMES.some(isPresent);
  const bridgePresent = BRIDGE_SECRET_NAMES.some(isPresent);
  if (provider === 'yubikey-piv') {
    if (softwarePresent || !BRIDGE_SECRET_NAMES.every(isPresent)) {
      throw new Error('The yubikey-piv provider requires all three bridge secrets and no supplied software encryption pair.');
    }
    return validateBridgeSecrets(env, siteUrl);
  }
  if (bridgePresent) throw new Error('Bridge secrets require the explicit yubikey-piv provider and cannot be mixed with software encryption secrets.');
  if (!SOFTWARE_SECRET_NAMES.every(isPresent)) throw new Error('Set both INTERNAL_LLMS_KEY and INTERNAL_LLMS_CIPHERTEXT together, or leave every internal document setting unset.');
  const key = env.INTERNAL_LLMS_KEY;
  if (key === env.AGENT_TOKEN || key === env.CLOUDFLARE_API_TOKEN) {
    throw new Error('INTERNAL_LLMS_KEY must be independent of AGENT_TOKEN and CLOUDFLARE_API_TOKEN.');
  }
  const additionalData = context(siteUrl);
  const keyBytes = decode(key, 32, 32);
  let plaintext;
  try {
    const { nonce, ciphertext } = parseEnvelope(env.INTERNAL_LLMS_CIPHERTEXT);
    const cryptoKey = await webcrypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    try {
      plaintext = new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, cryptoKey, ciphertext));
    } catch { throw new Error('Internal LLM document authentication failed; check the encryption key and site origin.'); }
    validatePlaintext(plaintext);
    return { INTERNAL_LLMS_PROVIDER: 'software', INTERNAL_LLMS_KEY: key, INTERNAL_LLMS_CIPHERTEXT: env.INTERNAL_LLMS_CIPHERTEXT };
  } finally {
    keyBytes.fill(0);
    plaintext?.fill(0);
  }
}
