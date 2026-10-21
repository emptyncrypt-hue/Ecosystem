import { describe, expect, it, vi } from 'vitest';
import { runInNewContext } from 'node:vm';
import { DASHBOARD_HTML } from '../src/dashboard';

class Element {
  style: Record<string, string> = {};
  hidden = false;
  disabled = false;
  value = '';
  private text = '';
  private html = '';
  get textContent() { return this.text; }
  set textContent(value: string) { this.text = value; this.html = ''; }
  get innerHTML() { return this.html; }
  set innerHTML(value: string) { this.html = value; this.text = ''; }
  focused = false;
  attrs: Record<string, string> = {};
  listeners: Record<string, (event: any) => void> = {};
  classList = { add: vi.fn(), remove: vi.fn(), toggle: vi.fn() };
  getAttribute(name: string) { return this.attrs[name] ?? null; }
  setAttribute(name: string, value: string) { this.attrs[name] = value; }
  removeAttribute(name: string) { delete this.attrs[name]; }
  addEventListener(name: string, listener: (event: any) => void) { this.listeners[name] = listener; }
  closest() { return this; }
  focus() { this.focused = true; }
}

type Session = { enabled: boolean; authenticated: boolean };
type RequestCall = { path: string; opts: RequestInit };
type Route = (call: RequestCall) => unknown | Promise<unknown>;
type HarnessOptions = {
  session?: Session | null;
  sessionStatus?: number;
  routes?: Record<string, Route>;
  secure?: boolean;
  supported?: boolean;
  storageBlocked?: boolean;
};
const binary = (values: number[]) => new Uint8Array(values).buffer;
const encoded = (values: number[]) => Buffer.from(values).toString('base64url');
const assertion = () => ({
  id: encoded([0, 255, 254]), rawId: binary([0, 255, 254]), type: 'public-key',
  response: {
    clientDataJSON: binary([251, 255, 0]), authenticatorData: binary([1, 2, 250]),
    signature: binary([255, 254]), userHandle: binary([0, 1, 255]),
  },
  getClientExtensionResults: () => ({ credProps: { rk: true } }),
  toJSON() { throw new Error('Older browsers do not implement credential.toJSON'); },
});
const attestation = () => ({
  id: encoded([4, 255, 251]), rawId: binary([4, 255, 251]), type: 'public-key',
  authenticatorAttachment: 'cross-platform',
  response: {
    clientDataJSON: binary([0, 251, 255]), attestationObject: binary([253, 254, 255]),
    getTransports: () => ['usb', 'nfc'],
  },
  getClientExtensionResults: () => ({}),
  toJSON() { throw new Error('Older browsers do not implement credential.toJSON'); },
});

function harness(options: HarnessOptions = {}) {
  const elements = new Map<string, Element>();
  for (const tag of DASHBOARD_HTML.matchAll(/<[a-z]+\b([^>]*)>/gi)) {
    const attributes: Record<string, string> = {};
    for (const attr of tag[1].matchAll(/([\w-]+)(?:="([^"]*)")?/g)) attributes[attr[1]] = attr[2] ?? '';
    if (!attributes.id) continue;
    const element = new Element();
    element.attrs = attributes;
    element.hidden = 'hidden' in attributes;
    element.disabled = 'disabled' in attributes;
    elements.set(attributes.id, element);
  }
  const listeners: Record<string, (event: any) => void> = {};
  const storage = {
    removeItem: vi.fn(() => { if (options.storageBlocked) throw new Error('storage blocked'); }),
    getItem: vi.fn(() => { throw new Error('must never read stored credentials'); }),
    setItem: vi.fn(() => { throw new Error('must never persist credentials'); }),
    clear: vi.fn(() => { throw new Error('must not clear unrelated browser storage'); }),
  };
  const sessionStorage = new Proxy({}, { get() { throw new Error('must not access sessionStorage'); } });
  const calls: RequestCall[] = [];
  const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  });
  const fetch = vi.fn(async (path: string, opts: RequestInit = {}) => {
    const call = { path, opts };
    calls.push(call);
    if (options.routes?.[path]) {
      const result = await options.routes[path](call);
      return result instanceof Response ? result : response(result);
    }
    if (path === '/auth/session') return response(options.session === undefined ? { enabled: true, authenticated: false } : options.session, options.sessionStatus);
    if (path === '/status') return response({});
    if (path === '/auth/passkeys') return response({ passkeys: [] });
    if (['/proposals?status=proposed', '/findings?status=open', '/findings?status=dismissed', '/changes'].includes(path)) return response([]);
    throw new Error('Unexpected fetch: ' + path);
  });
  const get = vi.fn(async () => assertion());
  const create = vi.fn(async () => attestation());
  const navigator = { credentials: { get, create } };
  Object.defineProperty(navigator, 'userAgent', { get() { throw new Error('OS detection must not gate passkeys'); } });
  runInNewContext(DASHBOARD_HTML.match(/<script>([\s\S]*?)<\/script>/)![1], {
    window: {
      isSecureContext: options.secure ?? true,
      PublicKeyCredential: options.supported === false ? undefined : function PublicKeyCredential() {},
      addEventListener: vi.fn(),
    },
    document: {
      getElementById: (id: string) => elements.get(id), querySelector: () => null,
      addEventListener: (name: string, listener: (event: any) => void) => { listeners[name] = listener; },
    },
    navigator, location: { hash: '' }, localStorage: storage, sessionStorage,
    fetch, Uint8Array, ArrayBuffer,
    atob: (text: string) => Buffer.from(text, 'base64').toString('binary'),
    btoa: (text: string) => Buffer.from(text, 'binary').toString('base64'),
    setTimeout: vi.fn(), clearTimeout: vi.fn(),
  });
  const element = (id: string) => elements.get(id)!;
  const click = (id: string) => listeners.click({ target: element(id) });
  const action = (name: string, id: string) => {
    const target = new Element();
    target.attrs = { 'data-act': name, 'data-id': id };
    listeners.click({ target });
  };
  return { calls, fetch, get, create, element, click, action, storage, response };
}
async function settle() {
  for (let i = 0; i < 4; i++) await new Promise<void>((resolve) => setImmediate(resolve));
}
function body(call: RequestCall) { return JSON.parse(String(call.opts.body)); }
function assertMutation(call: RequestCall, bearer?: string) {
  expect(call.opts.credentials).toBe('same-origin');
  expect(call.opts.cache).toBe('no-store');
  expect(call.opts.headers).toEqual({
    'Content-Type': 'application/json', 'X-SEO-CSRF': '1',
    ...(bearer ? { Authorization: 'Bearer ' + bearer } : {}),
  });
}

describe('dashboard browser authentication', () => {
  it('erases the old token, discovers the cookie session, and loads the dashboard without browser storage or bearer headers', async () => {
    const h = harness({ session: { enabled: true, authenticated: true } });
    await settle();
    expect(h.storage.removeItem).toHaveBeenCalledExactlyOnceWith('seo_agent_token');
    expect(h.storage.getItem).not.toHaveBeenCalled();
    expect(h.storage.setItem).not.toHaveBeenCalled();
    expect(h.storage.clear).not.toHaveBeenCalled();
    expect(h.element('app').style.display).toBe('');
    expect(h.element('setup-passkey').hidden).toBe(false);
    expect(h.calls.map((call) => call.path)).toContain('/status');
    for (const call of h.calls) {
      expect(call.opts.credentials).toBe('same-origin');
      expect(call.opts.headers).toEqual({});
    }
  });

  it('exchanges a typed recovery token for a cookie and never sends it to dashboard APIs', async () => {
    const h = harness({ routes: { '/auth/token': () => ({ authenticated: true }) } });
    await settle();
    h.element('tok').value = '  ephemeral-recovery-token  ';
    h.click('token-login');
    expect(h.element('tok').value).toBe('');
    await settle();
    const exchange = h.calls.find((call) => call.path === '/auth/token')!;
    assertMutation(exchange, 'ephemeral-recovery-token');
    expect(body(exchange)).toEqual({});
    expect(h.calls.find((call) => call.path === '/status')!.opts.headers).toEqual({});
    expect(h.storage.setItem).not.toHaveBeenCalled();
    expect(h.element('app').style.display).toBe('');
  });

  it.each([401, 503])('does not fall back to bearer dashboard access after recovery exchange fails with %i', async (status) => {
    const h = harness({ routes: {
      '/auth/token': () => new Response(JSON.stringify({ error: 'Recovery unavailable' }), { status }),
    } });
    await settle();
    h.element('tok').value = 'rejected-recovery'; h.click('token-login'); await settle();
    expect(h.calls.map((call) => call.path)).toEqual(['/auth/session', '/auth/token']);
    expect(h.element('app').style.display).toBe('none');
    expect(h.element('tok').value).toBe('');
    expect(h.element('token-login').disabled).toBe(false);
    expect(h.element('loginerr').textContent).toMatch(status === 401 ? /rejected/ : /unavailable/);
    expect(h.storage.setItem).not.toHaveBeenCalled();
  });

  it('decodes login options and serializes native assertion buffers without newer WebAuthn JSON APIs', async () => {
    const h = harness({ routes: {
      '/auth/login/options': () => ({ challengeId: 'login-challenge', options: {
        challenge: encoded([0, 255, 251, 128]), rpId: 'agent.example.com',
        userVerification: 'preferred', allowCredentials: [{ id: encoded([251, 255, 0]), type: 'public-key', transports: ['hybrid', 'usb'] }],
      } }),
      '/auth/login/verify': () => ({ authenticated: true }),
    } });
    await settle();
    h.click('passkey-login');
    await settle();
    expect(h.get).toHaveBeenCalledTimes(1);
    const publicKey = (h.get.mock.calls[0] as any)[0].publicKey;
    expect([...new Uint8Array(publicKey.challenge)]).toEqual([0, 255, 251, 128]);
    expect([...new Uint8Array(publicKey.allowCredentials[0].id)]).toEqual([251, 255, 0]);
    expect(publicKey.allowCredentials[0].transports).toEqual(['hybrid', 'usb']);
    expect(publicKey.userVerification).toBe('required');
    const verify = h.calls.find((call) => call.path === '/auth/login/verify')!;
    assertMutation(verify);
    expect(body(verify)).toEqual({ challengeId: 'login-challenge', response: {
      id: encoded([0, 255, 254]), rawId: encoded([0, 255, 254]), type: 'public-key',
      response: { clientDataJSON: encoded([251, 255, 0]), authenticatorData: encoded([1, 2, 250]), signature: encoded([255, 254]), userHandle: encoded([0, 1, 255]) },
      clientExtensionResults: { credProps: { rk: true } },
    } });
    expect(h.element('app').style.display).toBe('');
  });

  it('serializes a discoverable login credential with no user handle', async () => {
    const h = harness({ routes: {
      '/auth/login/options': () => ({ challengeId: 'discoverable', options: { challenge: encoded([255]), rpId: 'agent.example.com' } }),
      '/auth/login/verify': () => ({ authenticated: true }),
    } });
    h.get.mockImplementationOnce(async () => ({ ...assertion(), response: { ...assertion().response, userHandle: null } } as any));
    await settle(); h.click('passkey-login'); await settle();
    expect((h.get.mock.calls[0] as any)[0].publicKey.allowCredentials).toBeUndefined();
    expect(body(h.calls.find((call) => call.path === '/auth/login/verify')!).response.response.userHandle).toBeNull();
  });

  it('requires the protected administrator field for enrollment even with a valid session', async () => {
    const h = harness({ session: { enabled: true, authenticated: true } });
    await settle(); h.click('setup-passkey'); await settle();
    expect(h.element('passkey-setup').hidden).toBe(false);
    expect(h.element('admin-token').attrs.type).toBe('password');
    expect(h.element('admin-token').focused).toBe(true);
    h.click('register-passkey'); await settle();
    expect(h.element('passkey-status').textContent).toContain('administrator agent token');
    expect(h.calls.filter((call) => call.path.startsWith('/auth/register'))).toEqual([]);
    expect(h.create).not.toHaveBeenCalled();
  });

  it('uses the recovery bearer for both enrollment steps, requires verification, and permits platform or security-key authenticators', async () => {
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/auth/register/options': () => ({ challengeId: 'registration-challenge', options: {
        challenge: encoded([255, 0, 128]), rp: { id: 'agent.example.com', name: 'SEO Agent' },
        user: { id: encoded([251, 255]), name: 'administrator', displayName: 'Administrator' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'preferred' },
        excludeCredentials: [{ id: encoded([255, 254, 0]), type: 'public-key', transports: ['usb'] }],
      } }),
      '/auth/register/verify': () => ({ verified: true }),
    } });
    await settle(); h.click('setup-passkey'); await settle();
    h.element('admin-token').value = 'enrollment-recovery';
    h.element('passkey-label').value = '  Phone or YubiKey  ';
    h.click('register-passkey');
    expect(h.element('admin-token').value).toBe('');
    await settle();
    const publicKey = (h.create.mock.calls[0] as any)[0].publicKey;
    expect([...new Uint8Array(publicKey.challenge)]).toEqual([255, 0, 128]);
    expect([...new Uint8Array(publicKey.user.id)]).toEqual([251, 255]);
    expect([...new Uint8Array(publicKey.excludeCredentials[0].id)]).toEqual([255, 254, 0]);
    expect(publicKey.authenticatorSelection).toEqual({ residentKey: 'required', userVerification: 'required' });
    expect(publicKey.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }]);
    const registration = h.calls.filter((call) => call.path.startsWith('/auth/register/'));
    registration.forEach((call) => assertMutation(call, 'enrollment-recovery'));
    expect(body(registration[0])).toEqual({ label: 'Phone or YubiKey' });
    expect(body(registration[1])).toEqual({ challengeId: 'registration-challenge', response: {
      id: encoded([4, 255, 251]), rawId: encoded([4, 255, 251]), type: 'public-key', authenticatorAttachment: 'cross-platform',
      response: { clientDataJSON: encoded([0, 251, 255]), attestationObject: encoded([253, 254, 255]), transports: ['usb', 'nfc'] },
      clientExtensionResults: {},
    } });
    expect(h.element('passkey-status').textContent).toContain('Passkey created');
    expect(h.element('admin-token').value).toBe('');
    expect(h.element('passkey-label').value).toBe('');
    // A later enrollment cannot reuse the previous operation's token.
    h.click('register-passkey'); await settle();
    expect(h.calls.filter((call) => call.path.startsWith('/auth/register/'))).toHaveLength(2);
  });

  it('rejects an overlong enrollment label and clears the protected field', async () => {
    const h = harness({ session: { enabled: true, authenticated: true } });
    await settle();
    h.element('admin-token').value = 'one-use-token';
    h.element('passkey-label').value = 'x'.repeat(61);
    h.click('register-passkey'); await settle();
    expect(h.element('passkey-status').textContent).toContain('60 characters');
    expect(h.element('admin-token').value).toBe('');
    expect(h.create).not.toHaveBeenCalled();
    expect(h.calls.some((call) => call.path.startsWith('/auth/register/'))).toBe(false);
  });

  it.each(['', '   '])('enrolls with the default name when the optional passkey label is empty (%j)', async (label) => {
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/auth/register/options': (call) => {
        if (body(call).label !== 'Passkey') return new Response('{}', { status: 400 });
        return { challengeId: 'default-label', options: {
          challenge: encoded([255]), user: { id: encoded([0]) },
        } };
      },
      '/auth/register/verify': () => ({ verified: true }),
    } });
    await settle();
    h.element('admin-token').value = 'default-name-recovery';
    h.element('passkey-label').value = label;
    h.click('register-passkey'); await settle();
    const enrollment = h.calls.filter((call) => call.path.startsWith('/auth/register/'));
    expect(enrollment.map((call) => call.path)).toEqual(['/auth/register/options', '/auth/register/verify']);
    expect(body(enrollment[0])).toEqual({ label: 'Passkey' });
    expect(h.create).toHaveBeenCalledTimes(1);
    expect(h.element('passkey-status').textContent).toContain('Passkey created');
    expect(h.element('admin-token').value).toBe('');
  });

  it('clears enrollment recovery authorization after cancellation without losing the existing session', async () => {
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/auth/register/options': () => ({ challengeId: 'cancel-registration', options: {
        challenge: encoded([255]), user: { id: encoded([0]) },
      } }),
    } });
    h.create.mockRejectedValueOnce(Object.assign(new Error('Native cancellation'), { name: 'NotAllowedError' }));
    await settle();
    h.element('admin-token').value = 'canceled-recovery';
    h.click('register-passkey'); await settle();
    expect(h.element('admin-token').value).toBe('');
    expect(h.element('passkey-status').textContent).toContain('canceled or timed out');
    expect(h.element('app').style.display).toBe('');
    expect(h.element('register-passkey').disabled).toBe(false);
    h.click('register-passkey'); await settle();
    expect(h.calls.filter((call) => call.path.startsWith('/auth/register/'))).toHaveLength(1);
  });

  it('shows canceled requests inline, re-enables sign-in, and never verifies a canceled credential', async () => {
    const h = harness({ routes: {
      '/auth/login/options': () => ({ challengeId: 'cancel', options: { challenge: encoded([1]) } }),
    } });
    h.get.mockRejectedValueOnce(Object.assign(new Error('Native cancellation'), { name: 'NotAllowedError' }));
    await settle(); h.click('passkey-login'); await settle();
    expect(h.element('loginerr').textContent).toContain('canceled or timed out');
    expect(h.element('loginerr').attrs['aria-live']).toBe('polite');
    expect(h.element('passkey-login').disabled).toBe(false);
    expect(h.calls.some((call) => call.path === '/auth/login/verify')).toBe(false);
    expect(h.calls.some((call) => call.path === '/status')).toBe(false);
  });

  it.each([{ supported: false }, { secure: false }])('shows unsupported-browser errors before contacting options (%j)', async (capabilities) => {
    const h = harness(capabilities);
    await settle(); h.click('passkey-login'); await settle();
    expect(h.element('loginerr').textContent).toContain('Passkeys are unavailable in this browser');
    expect(h.calls.map((call) => call.path)).toEqual(['/auth/session']);
  });

  it.each([{ session: null }, { sessionStatus: 503 }])('fails closed when session discovery is unavailable (%j)', async (failure) => {
    const h = harness(failure);
    await settle();
    h.element('tok').value = 'must-not-fallback';
    h.click('token-login'); h.click('passkey-login');
    await settle();
    expect(h.element('loginerr').textContent).toContain('Unable to check sign-in availability');
    expect(h.element('token-login').disabled).toBe(true);
    expect(h.calls.map((call) => call.path)).toEqual(['/auth/session']);
    expect(h.storage.setItem).not.toHaveBeenCalled();
  });

  it('keeps an unconfigured deployment token only in page memory, including when storage is blocked', async () => {
    const h = harness({ session: { enabled: false, authenticated: false }, storageBlocked: true });
    await settle();
    h.element('tok').value = 'legacy-page-only'; h.click('token-login'); await settle();
    expect(h.calls.find((call) => call.path === '/status')!.opts.headers).toEqual({ Authorization: 'Bearer legacy-page-only' });
    expect(h.element('tok').value).toBe('');
    expect(h.element('setup-passkey').hidden).toBe(true);
    expect(h.storage.getItem).not.toHaveBeenCalled();
    expect(h.storage.setItem).not.toHaveBeenCalled();
    const count = h.calls.length;
    h.click('logout'); await settle();
    expect(h.element('app').style.display).toBe('none');
    expect(h.calls).toHaveLength(count);
    const reloaded = harness({ session: { enabled: false, authenticated: false } });
    await settle();
    expect(reloaded.calls.map((call) => call.path)).toEqual(['/auth/session']);
  });

  it('clears rendered data on logout before another legacy token can show the dashboard', async () => {
    let valid = true;
    const h = harness({ session: { enabled: false, authenticated: false }, routes: {
      '/status': () => valid ? {} : new Response('{}', { status: 401 }),
    } });
    await settle();
    h.element('tok').value = 'valid-legacy-token'; h.click('token-login'); await settle();
    expect(h.element('cards').innerHTML).toContain('Pending');
    h.element('drout').innerHTML = '<div>Previous draft</div>';
    h.click('logout');
    expect(h.element('cards').innerHTML).toBe('');
    expect(h.element('drout').innerHTML).toBe('');
    valid = false;
    h.element('tok').value = 'invalid-legacy-token'; h.click('token-login');
    expect(h.element('cards').innerHTML).toBe('');
    await settle();
    expect(h.element('app').style.display).toBe('none');
    expect(h.element('loginerr').textContent).toBe('Token rejected.');
  });

  it('discards dashboard responses that arrive after the user signs out', async () => {
    let finishStatus!: (value: unknown) => void;
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/status': () => new Promise((resolve) => { finishStatus = resolve; }),
      '/auth/logout': () => ({ authenticated: false }),
    } });
    await settle(); h.click('logout'); await settle();
    finishStatus({}); await settle();
    expect(h.element('cards').innerHTML).toBe('');
    expect(h.element('app').style.display).toBe('none');
  });

  it('requires a fresh recovery token to revoke a passkey and escapes labels in the list', async () => {
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/auth/passkeys': () => ({ passkeys: [{ id: 'credential_id', label: '<img src=x onerror=alert(1)>', createdAt: '2026-10-21T00:00:00Z' }] }),
      '/auth/passkeys/credential_id': () => ({ deleted: true }),
    } });
    await settle(); h.click('setup-passkey'); await settle();
    expect(h.element('passkey-list').innerHTML).toContain('&lt;img');
    expect(h.element('passkey-list').innerHTML).not.toContain('<img');
    h.action('revoke-passkey', 'credential_id'); await settle();
    expect(h.calls.some((call) => call.opts.method === 'DELETE')).toBe(false);
    h.element('admin-token').value = 'revoke-recovery';
    h.action('revoke-passkey', 'credential_id'); await settle();
    const revoke = h.calls.find((call) => call.opts.method === 'DELETE')!;
    assertMutation(revoke, 'revoke-recovery');
    expect(body(revoke)).toEqual({});
    expect(h.element('admin-token').value).toBe('');
    expect(h.element('passkey-status').textContent).toBe('Passkey revoked.');
  });

  it('signs out via a cookie-authorized JSON mutation and requires sign-in again', async () => {
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/auth/logout': () => ({ authenticated: false }),
    } });
    await settle(); h.click('logout'); await settle();
    const logout = h.calls.find((call) => call.path === '/auth/logout')!;
    assertMutation(logout);
    expect(body(logout)).toEqual({});
    expect(h.element('app').style.display).toBe('none');
    expect(h.element('login').style.display).toBe('');
    expect(h.element('admin-token').value).toBe('');
  });

  it('reports a failed server logout without falsely claiming the cookie session ended', async () => {
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/auth/logout': () => new Response('{}', { status: 503 }),
    } });
    await settle(); h.click('logout'); await settle();
    expect(h.element('app').style.display).toBe('');
    expect(h.element('toast').textContent).toContain('Sign-out is unavailable');
    expect(h.element('logout').disabled).toBe(false);
  });

  it('returns to sign-in when a cookie-authenticated dashboard API rejects the session', async () => {
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/status': () => new Response('{}', { status: 401 }),
    } });
    await settle();
    expect(h.element('app').style.display).toBe('none');
    expect(h.element('loginerr').textContent).toContain('session expired');
    expect(h.calls.every((call) => !(call.opts.headers as Record<string, string>).Authorization)).toBe(true);
  });

  it('adds JSON and CSRF headers to existing dashboard actions without a recovery bearer', async () => {
    const h = harness({ session: { enabled: true, authenticated: true }, routes: {
      '/run': () => ({ started: true }),
    } });
    await settle(); h.click('runbtn'); await settle();
    const run = h.calls.find((call) => call.path === '/run')!;
    assertMutation(run);
    expect(body(run)).toEqual({});
  });
});
