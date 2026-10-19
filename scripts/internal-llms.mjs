import { randomBytes, webcrypto } from 'node:crypto';

const encoder = new TextEncoder();
const MAX_PLAINTEXT_BYTES = 2048;
const MAX_ENVELOPE_BYTES = 4096;
const SECRET_NAMES = ['INTERNAL_LLMS_KEY', 'INTERNAL_LLMS_CIPHERTEXT'];

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

// Empty optional environment entries are absent (GitHub Actions resolves
// unconfigured secrets to empty strings). One present entry is never accepted.
// An absent pair leaves existing remote secrets intact during normal deploys.
export async function validateInternalLlmsSecrets({ env = {}, siteUrl } = {}) {
  const present = SECRET_NAMES.map(name => env[name] !== undefined && env[name] !== '');
  if (!present.some(Boolean)) return {};
  if (!present.every(Boolean)) throw new Error('Set both INTERNAL_LLMS_KEY and INTERNAL_LLMS_CIPHERTEXT together, or leave both unset.');
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
    return { INTERNAL_LLMS_KEY: key, INTERNAL_LLMS_CIPHERTEXT: env.INTERNAL_LLMS_CIPHERTEXT };
  } finally {
    keyBytes.fill(0);
    plaintext?.fill(0);
  }
}
