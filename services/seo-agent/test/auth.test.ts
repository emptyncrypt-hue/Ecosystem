import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';

// Exercise the HTTP boundary with real Request streams and WebCrypto. Successful
// ceremonies and expiry queries run separately against real D1 in workerd.
const ORIGIN = 'https://auth.example.com';
const FOREIGN_ORIGIN = 'https://foreign.example.com';
const TOKEN = 'synthetic-unit-test-agent-token';
const SESSION = '__Host-seo-session=' + 'A'.repeat(43);
const ctx = { waitUntil: vi.fn() } as unknown as ExecutionContext;

function fixture(overrides: Record<string, unknown> = {}): Env {
  return { AUTH_ORIGIN: ORIGIN, AGENT_TOKEN: TOKEN, SITE_URL: 'https://public.example.com', ...overrides } as unknown as Env;
}

function tripwireEnv(overrides: Record<string, unknown> = {}) {
  const touched: string[] = [];
  const env = fixture(overrides);
  for (const key of ['DB', 'AI', 'OVERRIDES', 'DRAFT_QUEUE', 'INTERNAL_LLMS_KEY', 'INTERNAL_LLMS_CIPHERTEXT', 'INTERNAL_LLMS_BRIDGE_TOKEN']) {
    Object.defineProperty(env, key, { get() { touched.push(key); throw new Error('forbidden dependency accessed'); } });
  }
  return { env, touched };
}

function request(path: string, {
  method = 'GET', origin = ORIGIN, headers = {}, body = '{}',
}: { method?: string; origin?: string; headers?: Record<string, string>; body?: string } = {}): Request {
  return new Request(origin + path, {
    method,
    headers: {
      ...(method === 'GET' || method === 'HEAD' ? {} : { origin: ORIGIN, 'content-type': 'application/json', 'x-seo-csrf': '1' }),
      ...headers,
    },
    ...(method === 'GET' || method === 'HEAD' ? {} : { body }),
  });
}

function watchBody(req: Request) {
  const read = vi.fn(() => { throw new Error('body read before authorization'); });
  Object.defineProperty(req, 'body', { get: read });
  return read;
}

function readyDB() {
  const prepare = vi.fn(() => {
    const statement = {
      bind: vi.fn(() => statement),
      first: vi.fn(async () => null),
      all: vi.fn(async () => ({ results: [] })),
      run: vi.fn(async () => ({ success: true, results: [], meta: { changes: 1 } })),
    };
    return statement;
  });
  const batch = vi.fn(async (statements: unknown[]) => statements.map(() => ({ success: true, results: [{}], meta: { changes: 1 } })));
  return { prepare, batch };
}

function expectPrivate(response: Response) {
  expect(response.headers.get('cache-control')).toContain('no-store');
  expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  for (const [name] of response.headers) expect(name.startsWith('access-control-')).toBe(false);
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('authentication authorization boundaries', () => {
  it.each([
    ['/auth/token', 'POST'], ['/auth/register/options', 'POST'], ['/auth/register/verify', 'POST'],
    ['/auth/passkeys/enrolled-key', 'DELETE'],
  ])('%s cannot create or revoke administrator access without a bearer token', async (path, method) => {
    const { env, touched } = tripwireEnv();
    Object.defineProperty(env, 'AGENT_TOKEN', { get() { touched.push('AGENT_TOKEN'); throw new Error('secret accessed before authorization'); } });
    const req = request(path, { method, headers: { cookie: SESSION } });
    const read = watchBody(req);
    const response = await worker.fetch(req, env, ctx);
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'unauthorized' });
    expect(read).not.toHaveBeenCalled();
    expect(touched).toEqual([]);
    expectPrivate(response);
  });

  it.each(['Bearer incorrect-token', 'Basic synthetic', '', `Bearer ${TOKEN} trailing`, `Bearer${TOKEN}`])('rejects an explicit invalid Authorization header without consulting a cookie: %j', async (authorization) => {
    const { env, touched } = tripwireEnv();
    const response = await worker.fetch(request('/overrides', { headers: { authorization, cookie: SESSION } }), env, ctx);
    expect(response.status).toBe(401);
    expect(touched).toEqual([]);
    expectPrivate(response);
  });

  it.each(['/mcp', '/internal/llms.txt', '/unrecognized-private-route'])('does not grant dashboard cookies access to %s', async (path) => {
    const { env, touched } = tripwireEnv();
    const response = await worker.fetch(request(path, { headers: { cookie: SESSION } }), env, ctx);
    expect(response.status).toBe(401);
    expect(touched).toEqual([]);
    expectPrivate(response);
  });

  it.each([
    '', '__Host-seo-session=short', '__Host-seo-session=' + 'A'.repeat(44),
    '__Host-seo-session=' + 'A'.repeat(42) + '=',
    '__Host-seo-session=' + 'A'.repeat(42) + '%', '__Host-seo-session=' + 'A'.repeat(42) + 'B',
    `${SESSION}; ${SESSION}`, `__Host-seo-session=; ${SESSION}`,
  ])('rejects malformed or ambiguous session cookies without querying D1: %j', async (cookie) => {
    const { env, touched } = tripwireEnv();
    const response = await worker.fetch(request('/overrides', { headers: { cookie } }), env, ctx);
    expect(response.status).toBe(401);
    expect(touched).toEqual([]);
  });

  it('keeps browser authentication disabled without configuration while bearer REST remains available', async () => {
    const { env, touched } = tripwireEnv({ AUTH_ORIGIN: undefined });
    const discovery = await worker.fetch(request('/auth/session'), env, ctx);
    expect(discovery.status).toBe(200);
    expect(await discovery.json()).toEqual({ enabled: false, authenticated: false });
    expect(touched).toEqual([]);
    const options = await worker.fetch(request('/auth/login/options', { method: 'POST' }), env, ctx);
    expect(options.status).toBe(503);
    expect(touched).toEqual([]);

    const list = vi.fn(async () => ({ keys: [] }));
    const bearer = await worker.fetch(request('/overrides', { headers: { authorization: `Bearer ${TOKEN}` } }), fixture({ AUTH_ORIGIN: undefined, OVERRIDES: { list } }), ctx);
    expect(bearer.status).toBe(200);
    expect(await bearer.json()).toEqual([]);
    expect(list).toHaveBeenCalledOnce();
  });
});

describe('origin, method, and request validation', () => {
  it.each([
    { origin: FOREIGN_ORIGIN },
    { origin: 'http://auth.example.com' },
    { headers: { origin: FOREIGN_ORIGIN } },
    { headers: { origin: 'null' } },
    { headers: { origin: '' } },
    { headers: { 'x-seo-csrf': '' } },
    { headers: { 'x-seo-csrf': 'true' } },
  ])('denies an unsafe authentication mutation before body or dependencies: %j', async (options) => {
    const { env, touched } = tripwireEnv();
    Object.defineProperty(env, 'AGENT_TOKEN', { get() { touched.push('AGENT_TOKEN'); throw new Error('secret accessed for foreign request'); } });
    const req = request('/auth/login/options', { method: 'POST', ...options });
    const read = watchBody(req);
    const response = await worker.fetch(req, env, ctx);
    expect(response.status).toBe(403);
    expect(read).not.toHaveBeenCalled();
    expect(touched).toEqual([]);
    expectPrivate(response);
  });

  it.each([
    { headers: { origin: FOREIGN_ORIGIN } },
    { headers: { origin: '' } },
    { headers: { 'x-seo-csrf': '' } },
    { headers: { 'content-type': 'text/plain' } },
    { origin: 'http://auth.example.com' },
    { origin: FOREIGN_ORIGIN },
  ])('denies unsafe cookie-authorized dashboard mutations before body, secret, or DB access: %j', async (options) => {
    const { env, touched } = tripwireEnv();
    Object.defineProperty(env, 'AGENT_TOKEN', { get() { touched.push('AGENT_TOKEN'); throw new Error('secret accessed for unsafe mutation'); } });
    const req = request('/proposals', { method: 'POST', ...options, headers: { cookie: SESSION, ...options.headers } });
    const read = watchBody(req);
    const response = await worker.fetch(req, env, ctx);
    expect(response.status).toBe(401);
    expect(read).not.toHaveBeenCalled();
    expect(touched).toEqual([]);
    expectPrivate(response);
  });

  it('uses configured RP identity despite hostile forwarding and Host headers', async () => {
    const db = readyDB();
    const response = await worker.fetch(request('/auth/login/options', { method: 'POST', headers: {
      host: 'attacker.example.com', 'x-forwarded-host': 'attacker.example.com', 'x-forwarded-proto': 'http',
    } }), fixture({ DB: db }), ctx);
    expect(response.status).toBe(200);
    const body = await response.json() as { options: { rpId: string; userVerification: string; allowCredentials?: unknown[] } };
    expect(body.options.rpId).toBe('auth.example.com');
    expect(body.options.userVerification).toBe('required');
    expect(body.options.allowCredentials).toBeUndefined();
    expectPrivate(response);
  });

  it.each(['http://auth.example.com', ORIGIN + '/', ORIGIN + '/path', ORIGIN + '?query', 'https://user:password@auth.example.com', ORIGIN + '#fragment'])('fails closed for an invalid configured origin: %s', async (authOrigin) => {
    const { env, touched } = tripwireEnv({ AUTH_ORIGIN: authOrigin });
    const response = await worker.fetch(request('/auth/session'), env, ctx);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: 'authentication unavailable' });
    expect(touched).toEqual([]);
  });

  it.each([
    ['/auth/login/options', 'GET'], ['/auth/login/verify', 'GET'], ['/auth/register/options', 'GET'],
    ['/auth/register/verify', 'GET'], ['/auth/token', 'GET'], ['/auth/logout', 'GET'],
    ['/auth/session', 'POST'], ['/auth/passkeys', 'POST'], ['/auth/login/options', 'PUT'],
    ['/auth/logout', 'OPTIONS'], ['/auth/token', 'HEAD'],
  ])('rejects unsupported %s %s before body or DB mutation', async (path, method) => {
    const { env, touched } = tripwireEnv();
    const req = request(path, { method });
    const read = watchBody(req);
    const response = await worker.fetch(req, env, ctx);
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBeTruthy();
    expect(read).not.toHaveBeenCalled();
    expect(touched).toEqual([]);
    expectPrivate(response);
  });

  it('rejects unknown authentication routes without reading the body or mutating state', async () => {
    const { env, touched } = tripwireEnv();
    const req = request('/auth/not-a-route', { method: 'POST' });
    const read = watchBody(req);
    const response = await worker.fetch(req, env, ctx);
    expect(response.status).toBe(404);
    expect(read).not.toHaveBeenCalled();
    expect(touched).toEqual([]);
  });

  it.each(['text/plain', 'application/x-www-form-urlencoded', '', 'application/json-patch+json'])('requires JSON on authentication mutations: %j', async (contentType) => {
    const { env, touched } = tripwireEnv();
    const req = request('/auth/login/options', { method: 'POST', headers: { 'content-type': contentType } });
    const read = watchBody(req);
    const response = await worker.fetch(req, env, ctx);
    expect(response.status).toBe(415);
    expect(read).not.toHaveBeenCalled();
    expect(touched).toEqual([]);
    expectPrivate(response);
  });

  it.each(['null', '[]', '"scalar"', '{'])('rejects invalid JSON objects before touching D1: %j', async (body) => {
    const { env, touched } = tripwireEnv();
    const response = await worker.fetch(request('/auth/login/options', { method: 'POST', body }), env, ctx);
    expect(response.status).toBe(400);
    expect(touched).toEqual([]);
  });

  it('bounds streamed request size even without Content-Length', async () => {
    const { env, touched } = tripwireEnv();
    const response = await worker.fetch(request('/auth/login/options', { method: 'POST', body: ' '.repeat(16 * 1024 + 1) }), env, ctx);
    expect(response.status).toBe(413);
    expect(touched).toEqual([]);
  });

  it('rejects an oversized declared body before reading its stream', async () => {
    const { env, touched } = tripwireEnv();
    const req = request('/auth/login/options', { method: 'POST', headers: { 'content-length': String(16 * 1024 + 1) } });
    const read = watchBody(req);
    const response = await worker.fetch(req, env, ctx);
    expect(response.status).toBe(413);
    expect(read).not.toHaveBeenCalled();
    expect(touched).toEqual([]);
  });

  it('times out a stalled body and cancels the stream without accessing D1', async () => {
    vi.useFakeTimers();
    const { env, touched } = tripwireEnv();
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({ cancel });
    const req = request('/auth/login/options', { method: 'POST' });
    let started!: () => void;
    const reading = new Promise<void>((resolve) => { started = resolve; });
    Object.defineProperty(req, 'body', { get() { started(); return stream; } });
    const pending = worker.fetch(req, env, ctx);
    await reading;
    await vi.advanceTimersByTimeAsync(5001);
    const response = await pending;
    expect(response.status).toBe(408);
    expect(cancel).toHaveBeenCalledOnce();
    expect(touched).toEqual([]);
    expectPrivate(response);
  });
});

describe('unavailable authentication storage', () => {
  it.each(['/auth/session', '/auth/token'])('returns a generic failure for missing tables without logging SDK/storage details: %s', async (path) => {
    const detail = 'D1_ERROR: no such table auth_sessions; synthetic database credential detail';
    const prepare = vi.fn(() => { throw new Error(detail); });
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
    const warnLog = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const response = await worker.fetch(request(path, {
      ...(path === '/auth/token' ? { method: 'POST' } : {}),
      headers: { authorization: `Bearer ${TOKEN}` },
    }), fixture({ DB: { prepare } }), ctx);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: 'authentication unavailable' });
    expect(prepare).toHaveBeenCalled();
    expect(errorLog).not.toHaveBeenCalled();
    expect(warnLog).not.toHaveBeenCalled();
    expectPrivate(response);
  });

  it('does not grant a session access when storage fails', async () => {
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
    const response = await worker.fetch(request('/overrides', { headers: { cookie: SESSION } }), fixture({
      DB: { prepare() { throw new Error('synthetic storage failure'); } },
    }), ctx);
    expect(response.status).toBe(401);
    expect(errorLog).not.toHaveBeenCalled();
    expectPrivate(response);
  });
});
