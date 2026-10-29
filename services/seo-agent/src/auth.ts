/** Origin-bound WebAuthn ceremonies and revocable dashboard-only sessions. */
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const SESSION_COOKIE = '__Host-seo-session';
const CHALLENGE_COOKIE = '__Host-seo-challenge';
const SESSION_TTL = 8 * 60 * 60;
const CHALLENGE_TTL = 5 * 60;
const MAX_BODY = 16 * 1024;
const MAX_KEYS = 20;
const MAX_CHALLENGES = 64;
const MAX_SESSIONS = 128;
const encoder = new TextEncoder();

type OriginConfig = { origin: string; rpID: string };
type AuthConfig = OriginConfig & { owner: string; userID: Uint8Array<ArrayBuffer> };
type RegistrationJSON = Parameters<typeof verifyRegistrationResponse>[0]['response'];
type AuthenticationJSON = Parameters<typeof verifyAuthenticationResponse>[0]['response'];
type Credential = Parameters<typeof verifyAuthenticationResponse>[0]['credential'];
type Passkey = {
  id: string; owner_epoch: string; label: string; public_key: string;
  counter: number; transports: string; created_at: number; revision: number;
};
type Challenge = { nonce: string; label: string | null };

class AuthError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

/** Apply to authentication replies and dashboard REST replies alike. */
export function privateAuthResponse(data: unknown, status = 200, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set('cache-control', 'private, no-store');
  responseHeaders.set('pragma', 'no-cache');
  responseHeaders.set('x-content-type-options', 'nosniff');
  responseHeaders.set('referrer-policy', 'no-referrer');
  return Response.json(data, { status, headers: responseHeaders });
}

function base64url(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64url(value: string): Uint8Array<ArrayBuffer> {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) throw new AuthError(400, 'invalid passkey response');
  try {
    const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    if (base64url(bytes) !== value) throw new Error('invalid encoding');
    return bytes;
  } catch { throw new AuthError(400, 'invalid passkey response'); }
}

function randomToken(): string { return base64url(crypto.getRandomValues(new Uint8Array(32))); }
async function digest(value: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}

async function constantEqual(left: string, right: string): Promise<boolean> {
  const [a, b] = await Promise.all([digest(left), digest(right)]);
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a[i] ^ b[i];
  return different === 0;
}

/** Explicit Authorization always takes precedence over dashboard cookies. */
export async function bearerAuthorized(request: Request, env: Env): Promise<boolean> {
  const header = request.headers.get('authorization');
  const match = header?.match(/^Bearer[ \t]+([^\s]+)$/i);
  if (!match || !env.AGENT_TOKEN) return false;
  return constantEqual(match[1], env.AGENT_TOKEN);
}

function originConfig(env: Env): OriginConfig | null {
  if (env.AUTH_ORIGIN === undefined || env.AUTH_ORIGIN === '') return null;
  try {
    const origin = env.AUTH_ORIGIN;
    const parsed = new URL(origin);
    const validHostname = parsed.hostname.length <= 253 && parsed.hostname.includes('.') &&
      parsed.hostname.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
    if (parsed.protocol !== 'https:' || parsed.origin !== origin || parsed.username || parsed.password ||
        parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.port ||
        !validHostname || /^(?:\d+\.){3}\d+$/.test(parsed.hostname) || /\.(?:localhost|local|internal)$/.test(parsed.hostname) ||
        new URL(env.SITE_URL).origin === origin) {
      throw new Error('invalid configuration');
    }
    return { origin, rpID: parsed.hostname };
  } catch { throw new AuthError(503, 'authentication unavailable'); }
}

async function config(env: Env, configuredOrigin = originConfig(env)): Promise<AuthConfig | null> {
  if (!configuredOrigin) return null;
  if (!env.AGENT_TOKEN) throw new AuthError(503, 'authentication unavailable');
  const owner = base64url(await digest(JSON.stringify(['seo-auth-owner-v1', env.AGENT_TOKEN, configuredOrigin.origin])));
  const userID = await digest(JSON.stringify(['seo-auth-user-v1', owner]));
  return { ...configuredOrigin, owner, userID };
}

function cookie(request: Request, name: string): string | null {
  const values = (request.headers.get('cookie') || '').split(';')
    .map(part => part.trim()).filter(part => part.startsWith(`${name}=`));
  if (values.length !== 1) return null;
  const value = values[0].slice(name.length + 1);
  return /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value) ? value : null;
}

function setCookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function requestOriginMatches(request: Request, cfg: OriginConfig): boolean {
  return new URL(request.url).origin === cfg.origin;
}

function mutationAllowed(request: Request, cfg: OriginConfig): boolean {
  return requestOriginMatches(request, cfg) && request.headers.get('origin') === cfg.origin &&
    request.headers.get('x-seo-csrf') === '1';
}

async function schemaReady(env: Env): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('SELECT 1 FROM auth_passkeys LIMIT 1'),
    env.DB.prepare('SELECT 1 FROM auth_challenges LIMIT 1'),
    env.DB.prepare('SELECT 1 FROM auth_sessions LIMIT 1'),
  ]);
}

async function sessionAuthorized(request: Request, env: Env, cfg: AuthConfig): Promise<boolean> {
  if (request.headers.has('authorization') || !requestOriginMatches(request, cfg)) return false;
  if (!['GET', 'HEAD'].includes(request.method) && (!mutationAllowed(request, cfg) ||
      (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase() !== 'application/json')) return false;
  const token = cookie(request, SESSION_COOKIE);
  if (!token) return false;
  const tokenHash = base64url(await digest(token));
  const session = await env.DB.prepare(`
    SELECT s.token_hash FROM auth_sessions s
    LEFT JOIN auth_passkeys p ON p.id = s.passkey_id AND p.owner_epoch = s.owner_epoch
    WHERE s.token_hash = ? AND s.owner_epoch = ? AND s.expires_at > ?
      AND (s.passkey_id IS NULL OR p.id IS NOT NULL)
  `).bind(tokenHash, cfg.owner, Math.floor(Date.now() / 1000)).first();
  return session !== null;
}

/** Call only for dashboard REST, never MCP or internal-LLMS resources. */
export async function dashboardSessionAuthorized(request: Request, env: Env): Promise<boolean> {
  try {
    if (request.headers.has('authorization') || !cookie(request, SESSION_COOKIE)) return false;
    const configuredOrigin = originConfig(env);
    if (!configuredOrigin || !requestOriginMatches(request, configuredOrigin)) return false;
    if (!['GET', 'HEAD'].includes(request.method) && (!mutationAllowed(request, configuredOrigin) ||
        (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase() !== 'application/json')) return false;
    const cfg = await config(env, configuredOrigin);
    return cfg !== null && await sessionAuthorized(request, env, cfg);
  } catch { return false; }
}

async function jsonBody(request: Request): Promise<Record<string, unknown>> {
  if ((request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase() !== 'application/json') {
    throw new AuthError(415, 'application/json required');
  }
  const contentLength = request.headers.get('content-length');
  if (contentLength && (!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_BODY)) {
    throw new AuthError(413, 'request body too large');
  }
  if (!request.body) throw new AuthError(400, 'invalid JSON body');
  const reader = request.body.getReader();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => reject(new AuthError(408, 'request body timeout')), 5000);
  });
  try {
    const chunks: Uint8Array[] = [];
    let length = 0;
    while (true) {
      const part = await Promise.race([reader.read(), deadline]);
      if (part.done) break;
      length += part.value.byteLength;
      if (length > MAX_BODY) throw new AuthError(413, 'request body too large');
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const body: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('invalid object');
    return body as Record<string, unknown>;
  } catch (error) {
    void reader.cancel().catch(() => {});
    if (error instanceof AuthError) throw error;
    throw new AuthError(400, 'invalid JSON body');
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    try { reader.releaseLock(); } catch { /* cancellation may still be pending */ }
  }
}

async function requireBearer(request: Request, env: Env): Promise<void> {
  if (!await bearerAuthorized(request, env)) throw new AuthError(401, 'unauthorized');
}

function transports(row: Passkey): Credential['transports'] {
  const values: unknown = JSON.parse(row.transports);
  if (!Array.isArray(values) || values.some(value => typeof value !== 'string')) throw new Error('invalid credential');
  return values as Credential['transports'];
}

async function createChallenge(env: Env, cfg: AuthConfig, purpose: 'register' | 'login', nonce: string, label: string | null): Promise<string> {
  const id = randomToken();
  const now = Math.floor(Date.now() / 1000);
  const results = await env.DB.batch([
    env.DB.prepare('DELETE FROM auth_challenges WHERE expires_at <= ?').bind(now),
    env.DB.prepare(`INSERT INTO auth_challenges (id, owner_epoch, purpose, origin, nonce, label, created_at, expires_at)
      SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM auth_challenges WHERE expires_at > ?) < ?
      RETURNING id`).bind(id, cfg.owner, purpose, cfg.origin, nonce, label, now, now + CHALLENGE_TTL, now, MAX_CHALLENGES),
  ]);
  if (!results[1].results.length) throw new AuthError(409, 'too many pending challenges');
  return id;
}

async function consumeChallenge(request: Request, env: Env, cfg: AuthConfig, body: Record<string, unknown>, purpose: 'register' | 'login'): Promise<Challenge> {
  const id = body.challengeId;
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(id) || cookie(request, CHALLENGE_COOKIE) !== id) {
    throw new AuthError(400, 'invalid passkey challenge');
  }
  const challenge = await env.DB.prepare(`DELETE FROM auth_challenges
    WHERE id = ? AND owner_epoch = ? AND origin = ? AND purpose = ? AND expires_at > ?
    RETURNING nonce, label`).bind(id, cfg.owner, cfg.origin, purpose, Math.floor(Date.now() / 1000)).first<Challenge>();
  if (!challenge) throw new AuthError(400, 'invalid passkey challenge');
  return challenge;
}

function ceremonyResponse(body: Record<string, unknown>, cfg: AuthConfig, ceremony: 'webauthn.create' | 'webauthn.get'): RegistrationJSON | AuthenticationJSON {
  const value = body.response;
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AuthError(400, 'invalid passkey response');
  const response = value as Record<string, unknown>;
  if (typeof response.id !== 'string' || response.id.length > 2048 || response.rawId !== response.id || response.type !== 'public-key') {
    throw new AuthError(400, 'invalid passkey response');
  }
  decodeBase64url(response.id);
  // Reject framed ceremonies explicitly: library origin checks alone do not
  // reject crossOrigin:true or a topOrigin supplied by an embedding page.
  try {
    const authenticatorResponse = response.response as Record<string, unknown> | undefined;
    if (!authenticatorResponse || typeof authenticatorResponse.clientDataJSON !== 'string') throw new Error('invalid client data');
    const clientData = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
      .decode(decodeBase64url(authenticatorResponse.clientDataJSON))) as Record<string, unknown>;
    if (clientData.origin !== cfg.origin || clientData.type !== ceremony ||
        (clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) || clientData.topOrigin !== undefined) {
      throw new Error('invalid client data');
    }
  } catch { throw new AuthError(400, 'invalid passkey response'); }
  return value as RegistrationJSON | AuthenticationJSON;
}

/** The unique marker makes session insertion depend on this batch's CAS update. */
async function createSession(env: Env, cfg: AuthConfig, passkey?: Passkey, newCounter?: number): Promise<string> {
  const token = randomToken();
  const tokenHash = base64url(await digest(token));
  const now = Math.floor(Date.now() / 1000);
  const statements: D1PreparedStatement[] = [env.DB.prepare('DELETE FROM auth_sessions WHERE expires_at <= ?').bind(now)];
  let insertIndex: number;
  if (passkey) {
    const marker = randomToken();
    statements.push(env.DB.prepare(`UPDATE auth_passkeys SET counter = ?, revision = revision + 1, last_auth_nonce = ?
      WHERE id = ? AND owner_epoch = ? AND counter = ? AND revision = ?`)
      .bind(newCounter!, marker, passkey.id, cfg.owner, passkey.counter, passkey.revision));
    insertIndex = statements.length;
    statements.push(env.DB.prepare(`INSERT INTO auth_sessions (token_hash, owner_epoch, passkey_id, created_at, expires_at)
      SELECT ?, ?, id, ?, ? FROM auth_passkeys
      WHERE id = ? AND owner_epoch = ? AND last_auth_nonce = ? AND revision = ? AND counter = ?`)
      .bind(tokenHash, cfg.owner, now, now + SESSION_TTL, passkey.id, cfg.owner, marker, passkey.revision + 1, newCounter!));
  } else {
    insertIndex = statements.length;
    statements.push(env.DB.prepare(`INSERT INTO auth_sessions (token_hash, owner_epoch, passkey_id, created_at, expires_at)
      VALUES (?, ?, NULL, ?, ?)`).bind(tokenHash, cfg.owner, now, now + SESSION_TTL));
  }
  statements.push(env.DB.prepare(`DELETE FROM auth_sessions WHERE owner_epoch = ? AND token_hash != ?
    AND EXISTS (SELECT 1 FROM auth_sessions WHERE token_hash = ?)
    AND token_hash NOT IN (SELECT token_hash FROM auth_sessions WHERE owner_epoch = ? AND token_hash != ?
      ORDER BY created_at DESC, token_hash DESC LIMIT ?)`)
    .bind(cfg.owner, tokenHash, tokenHash, cfg.owner, tokenHash, MAX_SESSIONS - 1));
  const results = await env.DB.batch(statements);
  if (results[insertIndex].meta.changes !== 1) throw new AuthError(400, 'invalid passkey response');
  return token;
}

export async function handleAuth(request: Request, env: Env): Promise<Response> {
  try {
    const path = new URL(request.url).pathname;
    const configuredOrigin = originConfig(env);
    if (request.method === 'GET' && path === '/auth/session' && !configuredOrigin) {
      return privateAuthResponse({ enabled: false, authenticated: false });
    }
    if (!configuredOrigin) throw new AuthError(503, 'authentication unavailable');
    if (!requestOriginMatches(request, configuredOrigin)) throw new AuthError(403, 'forbidden');
    const deleteKey = path.match(/^\/auth\/passkeys\/([A-Za-z0-9_-]+)$/);
    const expectedMethod = path === '/auth/session' || path === '/auth/passkeys' ? 'GET'
      : ['/auth/token', '/auth/logout', '/auth/register/options', '/auth/register/verify', '/auth/login/options', '/auth/login/verify'].includes(path) ? 'POST'
      : deleteKey ? 'DELETE' : null;
    if (!expectedMethod) return privateAuthResponse({ error: 'not found' }, 404);
    if (request.method !== expectedMethod) return privateAuthResponse({ error: 'method not allowed' }, 405, { allow: expectedMethod });
    const mutating = !['GET', 'HEAD'].includes(request.method);
    if (mutating && !mutationAllowed(request, configuredOrigin)) throw new AuthError(403, 'forbidden');
    const bearerRequired = path === '/auth/token' || path.startsWith('/auth/register/') || deleteKey !== null;
    const listWithBearer = path === '/auth/passkeys' && request.headers.has('authorization');
    if (bearerRequired || listWithBearer) await requireBearer(request, env);
    if (path === '/auth/passkeys' && !listWithBearer && !cookie(request, SESSION_COOKIE)) throw new AuthError(401, 'unauthorized');
    const body = mutating ? await jsonBody(request) : {};
    const cfg = await config(env, configuredOrigin);
    if (!cfg) throw new AuthError(503, 'authentication unavailable');
    await schemaReady(env);

    if (request.method === 'GET' && path === '/auth/session') {
      return privateAuthResponse({ enabled: true, authenticated: await bearerAuthorized(request, env) || await sessionAuthorized(request, env, cfg) });
    }
    if (request.method === 'POST' && path === '/auth/token') {
      const token = await createSession(env, cfg);
      return privateAuthResponse({ authenticated: true }, 200, { 'set-cookie': setCookie(SESSION_COOKIE, token, SESSION_TTL) });
    }
    if (request.method === 'POST' && path === '/auth/logout') {
      const token = cookie(request, SESSION_COOKIE);
      if (token) await env.DB.prepare('DELETE FROM auth_sessions WHERE token_hash = ? AND owner_epoch = ?')
        .bind(base64url(await digest(token)), cfg.owner).run();
      const headers = new Headers();
      headers.append('set-cookie', setCookie(SESSION_COOKIE, '', 0));
      headers.append('set-cookie', setCookie(CHALLENGE_COOKIE, '', 0));
      return privateAuthResponse({ authenticated: false }, 200, headers);
    }
    if (request.method === 'GET' && path === '/auth/passkeys') {
      if (!await bearerAuthorized(request, env) && !await sessionAuthorized(request, env, cfg)) throw new AuthError(401, 'unauthorized');
      const rows = await env.DB.prepare('SELECT id, label, created_at FROM auth_passkeys WHERE owner_epoch = ? ORDER BY created_at, id')
        .bind(cfg.owner).all<{ id: string; label: string; created_at: number }>();
      return privateAuthResponse({ passkeys: rows.results.map(row => ({ id: row.id, label: row.label, createdAt: new Date(row.created_at * 1000).toISOString() })) });
    }
    if (request.method === 'DELETE' && deleteKey) {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM auth_sessions WHERE owner_epoch = ? AND passkey_id = ?').bind(cfg.owner, deleteKey[1]),
        env.DB.prepare('DELETE FROM auth_passkeys WHERE owner_epoch = ? AND id = ?').bind(cfg.owner, deleteKey[1]),
      ]);
      return privateAuthResponse({ deleted: true });
    }
    if (request.method === 'POST' && path === '/auth/register/options') {
      if (typeof body.label !== 'string' || !body.label.trim() || [...body.label].length > 80 || /[\u0000-\u001f\u007f]/.test(body.label)) {
        throw new AuthError(400, 'label must contain 1 to 80 characters');
      }
      const keys = await env.DB.prepare('SELECT * FROM auth_passkeys WHERE owner_epoch = ?').bind(cfg.owner).all<Passkey>();
      if (keys.results.length >= MAX_KEYS) throw new AuthError(409, 'passkey limit reached');
      const nonce = randomToken();
      const options = await generateRegistrationOptions({
        rpName: 'SEO Agent', rpID: cfg.rpID, userID: cfg.userID, userName: 'owner', userDisplayName: 'SEO Agent owner',
        challenge: decodeBase64url(nonce), timeout: CHALLENGE_TTL * 1000, attestationType: 'none', supportedAlgorithmIDs: [-7, -257],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: keys.results.map(key => ({ id: key.id, transports: transports(key) })),
      });
      const challengeId = await createChallenge(env, cfg, 'register', nonce, body.label.trim());
      return privateAuthResponse({ options, challengeId }, 200, { 'set-cookie': setCookie(CHALLENGE_COOKIE, challengeId, CHALLENGE_TTL) });
    }
    if (request.method === 'POST' && path === '/auth/register/verify') {
      const challenge = await consumeChallenge(request, env, cfg, body, 'register');
      let registration: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
      try {
        registration = await verifyRegistrationResponse({
          response: ceremonyResponse(body, cfg, 'webauthn.create') as RegistrationJSON, expectedChallenge: challenge.nonce,
          expectedOrigin: cfg.origin, expectedRPID: cfg.rpID, requireUserVerification: true, supportedAlgorithmIDs: [-7, -257],
        });
      } catch { throw new AuthError(400, 'invalid passkey response'); }
      if (!registration.verified || !registration.registrationInfo) throw new AuthError(400, 'invalid passkey response');
      const credential = registration.registrationInfo.credential;
      const inserted = await env.DB.prepare(`INSERT INTO auth_passkeys (id, owner_epoch, label, public_key, counter, transports, created_at)
        SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM auth_passkeys WHERE owner_epoch = ?) < ?
          AND NOT EXISTS (SELECT 1 FROM auth_passkeys WHERE id = ?) RETURNING id`)
        .bind(credential.id, cfg.owner, challenge.label!, base64url(credential.publicKey), credential.counter,
          JSON.stringify(credential.transports || []), Math.floor(Date.now() / 1000), cfg.owner, MAX_KEYS, credential.id).first();
      if (!inserted) throw new AuthError(409, 'passkey could not be enrolled');
      return privateAuthResponse({ verified: true }, 200, { 'set-cookie': setCookie(CHALLENGE_COOKIE, '', 0) });
    }
    if (request.method === 'POST' && path === '/auth/login/options') {
      const nonce = randomToken();
      const options = await generateAuthenticationOptions({
        rpID: cfg.rpID, challenge: decodeBase64url(nonce), timeout: CHALLENGE_TTL * 1000, userVerification: 'required',
      });
      // Discoverable credentials: do not disclose an account/credential list.
      delete options.allowCredentials;
      const challengeId = await createChallenge(env, cfg, 'login', nonce, null);
      return privateAuthResponse({ options, challengeId }, 200, { 'set-cookie': setCookie(CHALLENGE_COOKIE, challengeId, CHALLENGE_TTL) });
    }
    if (request.method === 'POST' && path === '/auth/login/verify') {
      const challenge = await consumeChallenge(request, env, cfg, body, 'login');
      const response = ceremonyResponse(body, cfg, 'webauthn.get') as AuthenticationJSON;
      if (response.response?.userHandle !== base64url(cfg.userID)) throw new AuthError(400, 'invalid passkey response');
      const passkey = await env.DB.prepare('SELECT * FROM auth_passkeys WHERE id = ? AND owner_epoch = ?')
        .bind(response.id, cfg.owner).first<Passkey>();
      if (!passkey) throw new AuthError(400, 'invalid passkey response');
      let verified: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
      try {
        verified = await verifyAuthenticationResponse({
          response, expectedChallenge: challenge.nonce, expectedOrigin: cfg.origin, expectedRPID: cfg.rpID,
          credential: { id: passkey.id, publicKey: decodeBase64url(passkey.public_key), counter: passkey.counter, transports: transports(passkey) },
          requireUserVerification: true,
        });
      } catch { throw new AuthError(400, 'invalid passkey response'); }
      if (!verified.verified) throw new AuthError(400, 'invalid passkey response');
      const token = await createSession(env, cfg, passkey, verified.authenticationInfo.newCounter);
      const headers = new Headers();
      headers.append('set-cookie', setCookie(SESSION_COOKIE, token, SESSION_TTL));
      headers.append('set-cookie', setCookie(CHALLENGE_COOKIE, '', 0));
      return privateAuthResponse({ authenticated: true }, 200, headers);
    }
    return privateAuthResponse({ error: 'not found' }, 404);
  } catch (error) {
    if (error instanceof AuthError) return privateAuthResponse({ error: error.message }, error.status);
    // Do not return or log D1, credential, crypto-library, or secret-bearing errors.
    return privateAuthResponse({ error: 'authentication unavailable' }, 503);
  }
}
