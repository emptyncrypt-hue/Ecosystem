import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomBytes, timingSafeEqual, webcrypto } from 'node:crypto';
import worker from '../src/index';
import { handleInternalLlms } from '../src/internal-llms';

const TEXT = '# Synthetic bridge document\n\nLocal test fixture only.\n';
const URL = 'https://private-bridge.example.com/internal/llms.txt';
const KEY_ID = 'sha256:' + 'a'.repeat(64);
const ctx = { waitUntil: vi.fn() } as unknown as ExecutionContext;
let bridgeFetch: ReturnType<typeof vi.fn>;

function fixture(): Env {
  return {
    SITE_URL: 'https://www.dunesub.de', AGENT_TOKEN: 'synthetic-control-token',
    INTERNAL_LLMS_PROVIDER: 'yubikey-piv', INTERNAL_LLMS_BRIDGE_URL: URL,
    INTERNAL_LLMS_BRIDGE_TOKEN: randomBytes(32).toString('base64url'), INTERNAL_LLMS_BRIDGE_KEY_ID: KEY_ID,
  } as Env;
}
function request(method = 'GET', auth = true, scheme = 'https'): Request {
  return new Request(`${scheme}://agent.example.com/internal/llms.txt`, {
    method, headers: auth ? { Authorization: 'Bearer synthetic-control-token' } : {},
  });
}
function response(body: BodyInit | null = TEXT, headers: Record<string, string> = {}, status = 200): Response {
  return new Response(body, { status, headers: {
    'Content-Type': 'text/plain; charset=utf-8', 'X-Internal-LLMS-Key-ID': KEY_ID, ...headers,
  } });
}
function privateHeaders(res: Response) {
  expect(res.headers.get('cache-control')).toBe('private, no-store');
  expect(res.headers.get('x-robots-tag')).toBe('noindex, nofollow, noarchive');
  expect(res.headers.get('vary')).toBe('Authorization');
  expect(res.headers.get('content-security-policy')).toBe("default-src 'none'");
  expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  expect(res.headers.get('access-control-allow-origin')).toBeNull();
}
async function unavailable(env = fixture()) {
  const res = await handleInternalLlms(request(), env);
  expect(res.status).toBe(503);
  expect(await res.text()).toBe('Internal document unavailable\n');
  privateHeaders(res);
}

beforeEach(() => {
  vi.stubGlobal('crypto', { subtle: new Proxy(webcrypto.subtle, { get(target, name) {
    if (name === 'timingSafeEqual') return (a: ArrayBuffer, b: ArrayBuffer) => timingSafeEqual(Buffer.from(a), Buffer.from(b));
    const value = Reflect.get(target, name, target);
    return typeof value === 'function' ? value.bind(target) : value;
  } }) });
  bridgeFetch = vi.fn().mockImplementation(() => Promise.resolve(response()));
  vi.stubGlobal('fetch', bridgeFetch);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('authenticated YubiKey bridge provider', () => {
  it('uses only the independent bridge credential at the exact enrolled HTTPS endpoint', async () => {
    const env = fixture();
    Object.defineProperty(env, 'INTERNAL_LLMS_KEY', { get() { throw new Error('software key accessed in hardware mode'); } });
    Object.defineProperty(env, 'INTERNAL_LLMS_CIPHERTEXT', { get() { throw new Error('software fallback accessed'); } });
    for (const binding of ['DB', 'OVERRIDES', 'AI', 'DRAFT_QUEUE']) {
      Object.defineProperty(env, binding, { get() { throw new Error('document crossed a data boundary'); } });
    }
    const req = request();
    req.headers.set('x-private-input', 'must-not-forward');
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(TEXT);
    privateHeaders(res);
    expect(bridgeFetch).toHaveBeenCalledTimes(1);
    const [url, options] = bridgeFetch.mock.calls[0];
    expect(url).toBe(URL);
    expect(options).toMatchObject({ method: 'GET', redirect: 'manual', headers: {
      Authorization: `Bearer ${env.INTERNAL_LLMS_BRIDGE_TOKEN}`, Accept: 'text/plain', 'Cache-Control': 'no-store',
    } });
    expect(Object.keys(options.headers)).toHaveLength(3);
    expect(JSON.stringify(options.headers)).not.toContain(env.AGENT_TOKEN);
  });

  it.each(['GET', 'HEAD', 'POST', 'OPTIONS'])('authenticates outer %s before reading bridge configuration', async (method) => {
    const env = fixture();
    Object.defineProperty(env, 'INTERNAL_LLMS_BRIDGE_TOKEN', { get() { throw new Error('credential read before auth'); } });
    const res = await worker.fetch(request(method, false), env, ctx);
    expect(res.status).toBe(401);
    expect(await res.text()).toBe(method === 'HEAD' ? '' : 'Unauthorized\n');
    privateHeaders(res);
    expect(bridgeFetch).not.toHaveBeenCalled();
  });

  it('rejects a wrong control bearer before bridge contact', async () => {
    const req = request();
    req.headers.set('authorization', 'Bearer wrong-control-token');
    const res = await worker.fetch(req, fixture(), ctx);
    expect(res.status).toBe(401);
    expect(bridgeFetch).not.toHaveBeenCalled();
  });

  it('HEAD forwards HEAD for enrolled-device health without decrypting a document', async () => {
    bridgeFetch.mockResolvedValue(response(null, { 'Content-Length': '0' }));
    const res = await worker.fetch(request('HEAD'), fixture(), ctx);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('');
    privateHeaders(res);
    expect(bridgeFetch.mock.calls[0][1].method).toBe('HEAD');
  });

  it('fails closed for HEAD when the host cannot verify its device', async () => {
    bridgeFetch.mockResolvedValue(response(null, {}, 503));
    const res = await worker.fetch(request('HEAD'), fixture(), ctx);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe('');
    privateHeaders(res);
  });

  it.each(['POST', 'PUT', 'DELETE', 'OPTIONS'])('denies authorized %s without contacting the host', async (method) => {
    const res = await worker.fetch(request(method), fixture(), ctx);
    expect(res.status).toBe(405);
    privateHeaders(res);
    expect(bridgeFetch).not.toHaveBeenCalled();
  });

  it('denies HTTP before bridge contact', async () => {
    const res = await worker.fetch(request('GET', true, 'http'), fixture(), ctx);
    expect(res.status).toBe(403);
    expect(bridgeFetch).not.toHaveBeenCalled();
  });

  it.each([
    ['unknown provider', { INTERNAL_LLMS_PROVIDER: 'auto' }],
    ['empty provider', { INTERNAL_LLMS_PROVIDER: '' }],
    ['missing URL', { INTERNAL_LLMS_BRIDGE_URL: undefined }],
    ['HTTP URL', { INTERNAL_LLMS_BRIDGE_URL: URL.replace('https:', 'http:') }],
    ['IP URL', { INTERNAL_LLMS_BRIDGE_URL: 'https://127.0.0.1/internal/llms.txt' }],
    ['IPv6 URL', { INTERNAL_LLMS_BRIDGE_URL: 'https://[::1]/internal/llms.txt' }],
    ['numeric IP URL', { INTERNAL_LLMS_BRIDGE_URL: 'https://2130706433/internal/llms.txt' }],
    ['localhost URL', { INTERNAL_LLMS_BRIDGE_URL: 'https://localhost/internal/llms.txt' }],
    ['localhost subdomain URL', { INTERNAL_LLMS_BRIDGE_URL: 'https://bridge.localhost/internal/llms.txt' }],
    ['local-only DNS suffix', { INTERNAL_LLMS_BRIDGE_URL: 'https://bridge.local/internal/llms.txt' }],
    ['internal-only DNS suffix', { INTERNAL_LLMS_BRIDGE_URL: 'https://bridge.internal/internal/llms.txt' }],
    ['oversized URL', { INTERNAL_LLMS_BRIDGE_URL: 'https://' + 'bridge.'.repeat(80) + 'example.com/internal/llms.txt' }],
    ['alternate port', { INTERNAL_LLMS_BRIDGE_URL: 'https://private-bridge.example.com:8443/internal/llms.txt' }],
    ['credentials URL', { INTERNAL_LLMS_BRIDGE_URL: 'https://user:password@private-bridge.example.com/internal/llms.txt' }],
    ['query URL', { INTERNAL_LLMS_BRIDGE_URL: URL + '?token=x' }],
    ['fragment URL', { INTERNAL_LLMS_BRIDGE_URL: URL + '#private' }],
    ['wrong path', { INTERNAL_LLMS_BRIDGE_URL: URL.replace('/internal/', '/') }],
    ['public website origin', { INTERNAL_LLMS_BRIDGE_URL: 'https://www.dunesub.de/internal/llms.txt' }],
    ['recursive Worker origin', { INTERNAL_LLMS_BRIDGE_URL: 'https://agent.example.com/internal/llms.txt' }],
    ['missing token', { INTERNAL_LLMS_BRIDGE_TOKEN: undefined }],
    ['short token', { INTERNAL_LLMS_BRIDGE_TOKEN: 'a'.repeat(32) }],
    ['padded token', { INTERNAL_LLMS_BRIDGE_TOKEN: randomBytes(32).toString('base64url') + '=' }],
    ['control-token reuse', { INTERNAL_LLMS_BRIDGE_TOKEN: 'synthetic-control-token' }],
    ['missing key ID', { INTERNAL_LLMS_BRIDGE_KEY_ID: undefined }],
    ['malformed key ID', { INTERNAL_LLMS_BRIDGE_KEY_ID: 'SHA256:' + 'A'.repeat(64) }],
  ])('fails closed before fetch for %s, without AES fallback', async (_name, overrides) => {
    const env = { ...fixture(), ...overrides } as Env;
    const readSoftware = vi.fn(() => { throw new Error('fallback must never execute'); });
    Object.defineProperty(env, 'INTERNAL_LLMS_CIPHERTEXT', { get: readSoftware });
    await unavailable(env);
    expect(bridgeFetch).not.toHaveBeenCalled();
    expect(readSoftware).not.toHaveBeenCalled();
  });

  it('rejects reuse of a valid canonical control token as the bridge bearer', async () => {
    const env = fixture();
    env.AGENT_TOKEN = env.INTERNAL_LLMS_BRIDGE_TOKEN!;
    await unavailable(env);
    expect(bridgeFetch).not.toHaveBeenCalled();
  });

  it('explicit software mode does not contact the bridge when its envelope is unavailable', async () => {
    await unavailable({ ...fixture(), INTERNAL_LLMS_PROVIDER: 'software' });
    expect(bridgeFetch).not.toHaveBeenCalled();
  });

  it('rejects noncanonical bridge bearer padding bits', async () => {
    const env = fixture();
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const token = env.INTERNAL_LLMS_BRIDGE_TOKEN!;
    env.INTERNAL_LLMS_BRIDGE_TOKEN = token.slice(0, -1) + alphabet[alphabet.indexOf(token.at(-1)!) | 1];
    await unavailable(env);
    expect(bridgeFetch).not.toHaveBeenCalled();
  });

  it.each([301, 302, 401, 403, 404, 500, 503])('fails closed for upstream status %s', async (status) => {
    bridgeFetch.mockResolvedValue(response('untrusted upstream body', {}, status));
    await unavailable();
  });

  it('never follows an upstream redirect carrying the bridge credential to a different host', async () => {
    bridgeFetch.mockResolvedValue(response('redirect body', { Location: 'https://credential-sink.example.com/private' }, 302));
    await unavailable();
    expect(bridgeFetch).toHaveBeenCalledTimes(1);
    expect(bridgeFetch.mock.calls[0][0]).toBe(URL);
    expect(bridgeFetch.mock.calls[0][1].redirect).toBe('manual');
  });

  it.each([
    ['wrong media type', { 'Content-Type': 'text/html' }],
    ['wrong encoding', { 'Content-Type': 'text/plain; charset=iso-8859-1' }],
    ['missing pin', { 'X-Internal-LLMS-Key-ID': '' }],
    ['different enrolled key', { 'X-Internal-LLMS-Key-ID': 'sha256:' + 'b'.repeat(64) }],
    ['oversized declared content', { 'Content-Length': '2049' }],
    ['invalid declared content', { 'Content-Length': '-1' }],
    ['mismatched declared content', { 'Content-Length': '1' }],
  ])('rejects %s', async (_name, headers) => {
    bridgeFetch.mockResolvedValue(response(TEXT, headers));
    await unavailable();
  });

  it('rejects a response marked as redirected even if a fetch implementation follows it', async () => {
    const res = response();
    Object.defineProperty(res, 'redirected', { value: true });
    bridgeFetch.mockResolvedValue(res);
    await unavailable();
  });

  it('cancels rejected upstream responses without exposing upstream body text', async () => {
    const cancel = vi.fn();
    bridgeFetch.mockResolvedValue(response(new ReadableStream({ cancel }), { 'Content-Type': 'text/html' }));
    await unavailable();
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it('bounds streamed bytes independently of Content-Length', async () => {
    bridgeFetch.mockResolvedValue(response('x'.repeat(2048)));
    const res = await handleInternalLlms(request(), fixture());
    expect(res.status).toBe(200);
    expect(await res.text()).toHaveLength(2048);
    bridgeFetch.mockResolvedValue(response(new ReadableStream({ start(controller) {
      controller.enqueue(new Uint8Array(2048).fill(120));
      controller.enqueue(new Uint8Array([120]));
    } })));
    await unavailable();
  });

  it.each(['', 'test\0text', new Uint8Array([0xc3, 0x28])])('rejects empty, NUL, or malformed UTF8 content', async (body) => {
    bridgeFetch.mockResolvedValue(response(body));
    await unavailable();
  });

  it('bounds a stalled fetch at ten seconds and aborts it', async () => {
    vi.useFakeTimers();
    bridgeFetch.mockImplementation(() => new Promise(() => {}));
    const pending = unavailable();
    await vi.advanceTimersByTimeAsync(10_000);
    await pending;
    expect(bridgeFetch.mock.calls[0][1].signal.aborted).toBe(true);
  });

  it('bounds a stalled response reader and cancels it', async () => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    bridgeFetch.mockResolvedValue(response(new ReadableStream({ cancel })));
    const pending = unavailable();
    await vi.advanceTimersByTimeAsync(10_000);
    await pending;
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(bridgeFetch.mock.calls[0][1].signal.aborted).toBe(true);
  });

  it('does not disclose bridge exceptions, token, or body through logs', async () => {
    const env = fixture();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    bridgeFetch.mockRejectedValue(new Error(`${env.INTERNAL_LLMS_BRIDGE_TOKEN} ${TEXT}`));
    await unavailable(env);
    expect(log).not.toHaveBeenCalled();
  });
});
