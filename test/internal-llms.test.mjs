import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { sealInternalLlms, validateInternalLlmsSecrets } from '../scripts/internal-llms.mjs';

const siteUrl = 'https://www.dunesub.de';
const plaintext = '# DuneSub Ecosystem\n\nInternal reference. Use approved public platform documentation.\n';
const toEnv = ({ key, envelope }) => ({ INTERNAL_LLMS_KEY: key, INTERNAL_LLMS_CIPHERTEXT: envelope });

test('internal document roundtrips through an authenticated bounded envelope without plaintext in its serialization', async () => {
  const sealed = await sealInternalLlms({ plaintext, siteUrl });
  assert.equal(sealed.key.length, 43);
  assert.match(sealed.key, /^[A-Za-z0-9_-]+$/);
  const envelope = JSON.parse(sealed.envelope);
  assert.deepEqual(Object.keys(envelope), ['version', 'algorithm', 'nonce', 'ciphertext']);
  assert.equal(envelope.version, 1);
  assert.equal(envelope.algorithm, 'AES-256-GCM');
  assert.equal(Buffer.from(envelope.nonce, 'base64url').length, 12);
  assert.equal(Buffer.from(envelope.ciphertext, 'base64url').length, Buffer.byteLength(plaintext) + 16);
  assert.ok(!sealed.envelope.includes(plaintext));
  assert.deepEqual(await validateInternalLlmsSecrets({ env: toEnv(sealed), siteUrl: siteUrl + '/' }), toEnv(sealed));
});

test('encryption generates independent keys and fresh nonces even when a key is supplied', async () => {
  const first = await sealInternalLlms({ plaintext, siteUrl });
  const second = await sealInternalLlms({ plaintext, siteUrl });
  const reused = await sealInternalLlms({ plaintext, siteUrl, key: first.key });
  assert.notEqual(first.key, second.key);
  assert.equal(reused.key, first.key);
  assert.notEqual(JSON.parse(first.envelope).nonce, JSON.parse(reused.envelope).nonce);
  assert.notEqual(first.envelope, reused.envelope);
});

test('wrong keys, altered ciphertext, and a different site origin fail authentication without leaking sensitive values', async () => {
  const sealed = await sealInternalLlms({ plaintext, siteUrl });
  const other = await sealInternalLlms({ plaintext, siteUrl });
  const altered = JSON.parse(sealed.envelope);
  const ciphertext = Buffer.from(altered.ciphertext, 'base64url');
  ciphertext[0] ^= 1;
  altered.ciphertext = ciphertext.toString('base64url');
  const cases = [
    { env: { ...toEnv(sealed), INTERNAL_LLMS_KEY: other.key }, siteUrl },
    { env: { ...toEnv(sealed), INTERNAL_LLMS_CIPHERTEXT: JSON.stringify(altered) }, siteUrl },
    { env: toEnv(sealed), siteUrl: 'https://dunesub.de' },
  ];
  for (const input of cases) await assert.rejects(validateInternalLlmsSecrets(input), error => {
    assert.match(error.message, /authentication failed/);
    for (const secret of [plaintext, sealed.key, sealed.envelope, other.key]) assert.ok(!error.message.includes(secret));
    return true;
  });
});

test('optional secret pairs distinguish absent settings from partial or reused credentials', async () => {
  for (const env of [{}, { INTERNAL_LLMS_KEY: '', INTERNAL_LLMS_CIPHERTEXT: '' }, { INTERNAL_LLMS_KEY: '' }]) {
    assert.deepEqual(await validateInternalLlmsSecrets({ env, siteUrl }), {});
  }
  const sealed = await sealInternalLlms({ plaintext, siteUrl });
  for (const env of [
    { INTERNAL_LLMS_KEY: sealed.key }, { INTERNAL_LLMS_CIPHERTEXT: sealed.envelope },
    { ...toEnv(sealed), INTERNAL_LLMS_CIPHERTEXT: '' },
  ]) await assert.rejects(validateInternalLlmsSecrets({ env, siteUrl }), /both/);
  for (const name of ['AGENT_TOKEN', 'CLOUDFLARE_API_TOKEN']) {
    await assert.rejects(validateInternalLlmsSecrets({ env: { ...toEnv(sealed), [name]: sealed.key }, siteUrl }), /independent/);
  }
});

test('keys and envelope fields require canonical base64url and exact schema', async () => {
  const sealed = await sealInternalLlms({ plaintext, siteUrl });
  const original = JSON.parse(sealed.envelope);
  for (const key of [sealed.key + '=', sealed.key + '\n', 'A'.repeat(42), Buffer.alloc(31).toString('base64url'), null, ' '.repeat(43)]) {
    await assert.rejects(validateInternalLlmsSecrets({ env: { ...toEnv(sealed), INTERNAL_LLMS_KEY: key }, siteUrl }), /encoding/);
  }
  const noncanonicalKey = sealed.key.slice(0, -1) + 'B'; // Nonzero unused low bits for a 32-byte key.
  await assert.rejects(sealInternalLlms({ plaintext, siteUrl, key: noncanonicalKey }), /encoding/);
  for (const envelope of [
    null, [], {}, { ...original, version: 2 }, { ...original, algorithm: 'AES-256-XTS' },
    { ...original, extra: 'not permitted' }, { ...original, nonce: original.nonce + '=' },
    { ...original, nonce: Buffer.alloc(13).toString('base64url') },
    { ...original, ciphertext: original.ciphertext + '\n' },
    { ...original, ciphertext: Buffer.alloc(16).toString('base64url') },
    { ...original, ciphertext: Buffer.alloc(2065).toString('base64url') },
  ]) await assert.rejects(validateInternalLlmsSecrets({ env: { ...toEnv(sealed), INTERNAL_LLMS_CIPHERTEXT: JSON.stringify(envelope) }, siteUrl }));
  for (const envelope of ['not JSON', ' '.repeat(4097), 1]) {
    await assert.rejects(validateInternalLlmsSecrets({ env: { ...toEnv(sealed), INTERNAL_LLMS_CIPHERTEXT: envelope }, siteUrl }));
  }
});

test('document bounds count UTF-8 bytes and reject NUL, malformed Unicode, and unsafe site contexts', async () => {
  await sealInternalLlms({ plaintext: 'ä'.repeat(1024), siteUrl });
  for (const value of ['', 'x'.repeat(2049), 'ä'.repeat(1025), 'private\0text', '\ud800', null]) {
    await assert.rejects(sealInternalLlms({ plaintext: value, siteUrl }));
  }
  for (const origin of ['http://www.dunesub.de', 'https://user:password@www.dunesub.de', siteUrl + '/internal', siteUrl + '?preview=true', siteUrl + '#fragment', 'invalid']) {
    await assert.rejects(sealInternalLlms({ plaintext, siteUrl: origin }), /HTTPS site origin/);
  }
});

test('authentication alone does not accept binary, empty, or NUL plaintext', async () => {
  const sealed = await sealInternalLlms({ plaintext, siteUrl });
  const key = await webcrypto.subtle.importKey('raw', Buffer.from(sealed.key, 'base64url'), 'AES-GCM', false, ['encrypt']);
  for (const bytes of [new Uint8Array(), new Uint8Array([0xff]), new Uint8Array([65, 0, 66])]) {
    const nonce = webcrypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128,
      additionalData: new TextEncoder().encode(`dunesub-internal-llms:v1\n${siteUrl}\n/internal/llms.txt`) }, key, bytes);
    const envelope = JSON.stringify({ version: 1, algorithm: 'AES-256-GCM', nonce: Buffer.from(nonce).toString('base64url'), ciphertext: Buffer.from(ciphertext).toString('base64url') });
    await assert.rejects(validateInternalLlmsSecrets({ env: { INTERNAL_LLMS_KEY: sealed.key, INTERNAL_LLMS_CIPHERTEXT: envelope }, siteUrl }));
  }
});
