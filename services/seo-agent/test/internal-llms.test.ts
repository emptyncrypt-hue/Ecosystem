import { afterAll, describe, expect, it, vi } from 'vitest';
import { createCipheriv, randomBytes, timingSafeEqual, webcrypto } from 'node:crypto';
import worker from '../src/index';
import { handleInternalLlms, INTERNAL_LLMS_PATH } from '../src/internal-llms';

// Node's WebCrypto omits workerd's timingSafeEqual extension used by the
// existing AGENT_TOKEN gate. Keep actual WebCrypto for every cipher operation.
vi.stubGlobal('crypto', {
  subtle: new Proxy(webcrypto.subtle, { get(target, name) {
    if (name === 'timingSafeEqual') return (a: ArrayBuffer, b: ArrayBuffer) => timingSafeEqual(Buffer.from(a), Buffer.from(b));
    const value = Reflect.get(target, name, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } }),
});
afterAll(() => vi.unstubAllGlobals());

const SITE = 'https://www.dunesub.de';
const TEST_TEXT = '# Synthetic private document\n\nTest-only policy notes.\n';
const AAD = `dunesub-internal-llms:v1\n${SITE}\n${INTERNAL_LLMS_PATH}`;
const ctx = { waitUntil: vi.fn() } as unknown as ExecutionContext;

function fixture(content: string | Uint8Array = TEST_TEXT, options: { key?: Buffer; nonce?: Buffer; aad?: string } = {}): Env {
  const key = options.key || randomBytes(32);
  const nonce = options.nonce || randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(options.aad ?? AAD));
  const ciphertext = Buffer.concat([cipher.update(content), cipher.final(), cipher.getAuthTag()]);
  return {
    SITE_URL: SITE, AGENT_TOKEN: 'synthetic-test-authorization',
    INTERNAL_LLMS_KEY: key.toString('base64url'),
    INTERNAL_LLMS_CIPHERTEXT: JSON.stringify({ version: 1, algorithm: 'AES-256-GCM', nonce: nonce.toString('base64url'), ciphertext: ciphertext.toString('base64url') }),
  } as Env;
}

function request(method = 'GET', { auth = true, url = `https://agent.invalid${INTERNAL_LLMS_PATH}` } = {}): Request {
  return new Request(url, { method, headers: auth ? { authorization: 'Bearer synthetic-test-authorization' } : {} });
}

function assertPrivateHeaders(response: Response) {
  expect(response.headers.get('cache-control')).toBe('private, no-store');
  expect(response.headers.get('x-robots-tag')).toBe('noindex, nofollow, noarchive');
  expect(response.headers.get('vary')).toBe('Authorization');
  expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  expect(response.headers.get('content-security-policy')).toBe("default-src 'none'");
  expect(response.headers.get('access-control-allow-origin')).toBeNull();
}

async function assertUnavailable(env: Env) {
  const response = await handleInternalLlms(request(), env);
  expect(response.status).toBe(503);
  expect(await response.text()).toBe('Internal document unavailable\n');
  assertPrivateHeaders(response);
}

function editEnvelope(env: Env, edit: (envelope: Record<string, unknown>) => unknown): Env {
  return { ...env, INTERNAL_LLMS_CIPHERTEXT: JSON.stringify(edit(JSON.parse(env.INTERNAL_LLMS_CIPHERTEXT!))) };
}

describe('private encrypted llms document', () => {
  it('decrypts an independently sealed AES-256-GCM document only after authorization', async () => {
    const env = fixture();
    const touched: PropertyKey[] = [];
    const guarded = new Proxy(env, { get(target, property, receiver) {
      touched.push(property);
      if (['AI', 'DB', 'OVERRIDES', 'DRAFT_QUEUE'].includes(String(property))) throw new Error('private data crossed a policy boundary');
      return Reflect.get(target, property, receiver);
    } });
    const response = await worker.fetch(request(), guarded, ctx);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(TEST_TEXT);
    assertPrivateHeaders(response);
    expect(touched).not.toContain('DB');
    expect(ctx.waitUntil).not.toHaveBeenCalled();
  });

  it.each(['GET', 'HEAD', 'POST', 'OPTIONS'])('rejects unauthenticated %s before reading ciphertext', async (method) => {
    const env = fixture();
    Object.defineProperty(env, 'INTERNAL_LLMS_CIPHERTEXT', { get() { throw new Error('ciphertext read before authorization'); } });
    const response = await worker.fetch(request(method, { auth: false }), env, ctx);
    expect(response.status).toBe(401);
    expect(await response.text()).toBe(method === 'HEAD' ? '' : 'Unauthorized\n');
    assertPrivateHeaders(response);
  });

  it('rejects a wrong bearer token before decrypting', async () => {
    const env = fixture();
    Object.defineProperty(env, 'INTERNAL_LLMS_KEY', { get() { throw new Error('key read before authorization'); } });
    const req = request();
    req.headers.set('authorization', 'Bearer wrong-synthetic-token');
    const response = await worker.fetch(req, env, ctx);
    expect(response.status).toBe(401);
    assertPrivateHeaders(response);
  });

  it('returns a bodyless successful HEAD with the same private headers', async () => {
    const response = await worker.fetch(request('HEAD'), fixture(), ctx);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('');
    assertPrivateHeaders(response);
  });

  it('keeps a failed HEAD bodyless', async () => {
    const response = await worker.fetch(request('HEAD'), { ...fixture(), INTERNAL_LLMS_KEY: undefined }, ctx);
    expect(response.status).toBe(503);
    expect(await response.text()).toBe('');
    assertPrivateHeaders(response);
  });

  it.each(['POST', 'PUT', 'DELETE', 'OPTIONS'])('rejects authorized %s with 405 before reading secrets', async (method) => {
    const env = fixture();
    Object.defineProperty(env, 'INTERNAL_LLMS_KEY', { get() { throw new Error('key read for invalid method'); } });
    const response = await worker.fetch(request(method), env, ctx);
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD');
    assertPrivateHeaders(response);
  });

  it('denies plaintext over HTTP while leaving existing control routes unchanged', async () => {
    const response = await worker.fetch(request('GET', { url: `http://agent.invalid${INTERNAL_LLMS_PATH}` }), fixture(), ctx);
    expect(response.status).toBe(403);
    expect(await response.text()).toBe('Forbidden\n');
    assertPrivateHeaders(response);
    const dashboard = await worker.fetch(new Request('http://agent.invalid/dashboard'), fixture(), ctx);
    expect(dashboard.status).toBe(200);
  });

  it('does not expose the private document at the public path or a prefix match', async () => {
    for (const path of ['/llms.txt', '/internal/llms.txt/', '/internal/llms.txt.bak']) {
      const response = await worker.fetch(request('GET', { url: `https://agent.invalid${path}` }), fixture(), ctx);
      expect(response.status).toBe(404);
      expect(await response.text()).not.toContain(TEST_TEXT);
    }
  });

  it('accepts exactly 2048 plaintext bytes and rejects 2049', async () => {
    const response = await handleInternalLlms(request(), fixture('x'.repeat(2048)));
    expect(response.status).toBe(200);
    expect(await response.text()).toHaveLength(2048);
    await assertUnavailable(fixture('x'.repeat(2049)));
  });

  it.each([
    ['missing key', (env: Env) => ({ ...env, INTERNAL_LLMS_KEY: undefined })],
    ['missing ciphertext', (env: Env) => ({ ...env, INTERNAL_LLMS_CIPHERTEXT: undefined })],
    ['padded key', (env: Env) => ({ ...env, INTERNAL_LLMS_KEY: env.INTERNAL_LLMS_KEY + '=' })],
    ['short key', (env: Env) => ({ ...env, INTERNAL_LLMS_KEY: randomBytes(31).toString('base64url') })],
    ['wrong key', (env: Env) => ({ ...env, INTERNAL_LLMS_KEY: randomBytes(32).toString('base64url') })],
    ['key reused as auth token', (env: Env) => ({ ...env, AGENT_TOKEN: env.INTERNAL_LLMS_KEY! })],
    ['invalid JSON', (env: Env) => ({ ...env, INTERNAL_LLMS_CIPHERTEXT: '{' })],
    ['oversized envelope', (env: Env) => ({ ...env, INTERNAL_LLMS_CIPHERTEXT: ' '.repeat(4097) })],
    ['array envelope', (env: Env) => ({ ...env, INTERNAL_LLMS_CIPHERTEXT: '[]' })],
    ['null envelope', (env: Env) => ({ ...env, INTERNAL_LLMS_CIPHERTEXT: 'null' })],
    ['extra envelope key', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, plaintext: 'not a fallback' }))],
    ['missing envelope key', (env: Env) => editEnvelope(env, ({ nonce: _nonce, ...envelope }) => envelope)],
    ['wrong version', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, version: 2 }))],
    ['string version', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, version: '1' }))],
    ['wrong algorithm', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, algorithm: 'AES-256-XTS' }))],
    ['short nonce', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, nonce: randomBytes(11).toString('base64url') }))],
    ['padded nonce', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, nonce: envelope.nonce + '=' }))],
    ['non-string nonce', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, nonce: 12 }))],
    ['padded ciphertext', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, ciphertext: envelope.ciphertext + '=' }))],
    ['non-string ciphertext', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, ciphertext: [] }))],
    ['missing authentication tag', (env: Env) => editEnvelope(env, (envelope) => ({ ...envelope, ciphertext: randomBytes(15).toString('base64url') }))],
    ['wrong site origin', (env: Env) => ({ ...env, SITE_URL: 'https://other.invalid' })],
    ['HTTP site origin', (env: Env) => ({ ...env, SITE_URL: 'http://www.dunesub.de' })],
    ['credential-bearing site URL', (env: Env) => ({ ...env, SITE_URL: 'https://user:pass@www.dunesub.de' })],
    ['site path', (env: Env) => ({ ...env, SITE_URL: SITE + '/other' })],
    ['site query', (env: Env) => ({ ...env, SITE_URL: SITE + '/?other' })],
    ['site fragment', (env: Env) => ({ ...env, SITE_URL: SITE + '/#other' })],
  ])('fails closed for %s', async (_name, mutate) => {
    await assertUnavailable(mutate(fixture()));
  });

  it.each(['ciphertext', 'nonce'])('rejects authenticated encryption tampering in %s', async (field) => {
    const env = editEnvelope(fixture(), (envelope) => {
      const bytes = Buffer.from(envelope[field] as string, 'base64url');
      bytes[0] ^= 1;
      return { ...envelope, [field]: bytes.toString('base64url') };
    });
    await assertUnavailable(env);
  });

  it('rejects noncanonical base64url even when it decodes to the same key', async () => {
    const env = fixture();
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const key = env.INTERNAL_LLMS_KEY!;
    const changedPaddingBits = key.slice(0, -1) + alphabet[alphabet.indexOf(key.at(-1)!) | 1];
    expect(Buffer.from(changedPaddingBits, 'base64url')).toEqual(Buffer.from(key, 'base64url'));
    await assertUnavailable({ ...env, INTERNAL_LLMS_KEY: changedPaddingBits });
  });

  it('binds the ciphertext to the version, origin, and exact path via AAD', async () => {
    await assertUnavailable(fixture(TEST_TEXT, { aad: AAD.replace(':v1', ':v2') }));
    await assertUnavailable(fixture(TEST_TEXT, { aad: AAD.replace('/internal/llms.txt', '/llms.txt') }));
  });

  it('rejects invalid UTF-8, NUL-containing text, and an empty document after decryption', async () => {
    await assertUnavailable(fixture(new Uint8Array([0xc3, 0x28])));
    await assertUnavailable(fixture('synthetic\0text'));
    await assertUnavailable(fixture(''));
  });

  it('never logs decrypted content or cipher failure details', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      await assertUnavailable({ ...fixture(), INTERNAL_LLMS_KEY: randomBytes(32).toString('base64url') });
      expect(log).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
    }
  });
});
