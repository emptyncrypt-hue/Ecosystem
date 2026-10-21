import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { syntheticAuthenticator } from './lib/webauthn-fixture.mjs';

// These ceremonies run the shipped bundle in workerd with real SQLite-backed
// D1. Node builds independent CBOR/COSE fixtures and signs assertions; no crypto
// verifier, authentication module, or D1 implementation is mocked.
const serviceUrl = new URL('../services/seo-agent/', import.meta.url);
const serviceRequire = createRequire(new URL('package.json', serviceUrl));
const { Miniflare, Log, LogLevel } = serviceRequire('miniflare');
const workerPath = fileURLToPath(new URL('dist/index.js', serviceUrl));
await readFile(workerPath);
const stateDir = await mkdtemp(join(tmpdir(), 'ecosystem-seo-auth-'));
const origin = 'https://auth.example.com';
const foreignOrigin = 'https://foreign.example.com';
let token = randomBytes(32).toString('base64url');
let outboundRequests = 0;
let runtime;
let checks = 0;

const hash = (value) => createHash('sha256').update(value).digest('base64url');
const cookiePair = (response, name) => {
  const cookies = response.headers.getSetCookie();
  const match = cookies.find((value) => value.startsWith(`${name}=`));
  assert.ok(match, `Expected ${name} cookie`);
  return { header: match, pair: match.split(';', 1)[0], value: match.split(';', 1)[0].slice(name.length + 1) };
};
const sessionCookie = (response) => cookiePair(response, '__Host-seo-session');
const challengeCookie = (response) => cookiePair(response, '__Host-seo-challenge');

try {
  const options = {
    modules: true,
    scriptPath: workerPath,
    compatibilityDate: '2025-06-17',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    defaultPersistRoot: stateDir,
    cachePersist: false,
    d1Databases: { DB: 'seo-agent-auth-db' },
    d1Persist: join(stateDir, 'd1'),
    kvNamespaces: ['OVERRIDES'],
    kvPersist: join(stateDir, 'kv'),
    queueProducers: { DRAFT_QUEUE: 'seo-agent-auth-drafts' },
    bindings: {
      AGENT_TOKEN: token,
      AUTH_ORIGIN: origin,
      SITE_URL: 'https://public.example.com',
      SITE_NAME: 'Synthetic runtime fixture',
      AUTO_APPLY_FIELDS: '',
      AEO_CHECKS: 'false',
      CITATION_QUERIES: '[]',
    },
    outboundService: () => {
      outboundRequests += 1;
      throw new Error('Outbound requests are disabled during the passkey integration check');
    },
  };
  runtime = new Miniflare(options);
  let db = await runtime.getD1Database('DB');
  const schema = await readFile(new URL('schema.sql', serviceUrl), 'utf8');
  const statements = schema.replace(/--[^\n]*/g, '').split(';').map((sql) => sql.trim()).filter(Boolean);
  await db.batch(statements.map((sql) => db.prepare(sql)));

  async function request(path, { method = 'GET', body, bearer = false, cookie, headers = {}, csrf = true, expectedStatus = 200, requestOrigin = origin } = {}) {
    const requestHeaders = { ...headers };
    if (method !== 'GET' && method !== 'HEAD') {
      if (!Object.hasOwn(requestHeaders, 'content-type')) requestHeaders['content-type'] = 'application/json';
      if (csrf) {
        if (!Object.hasOwn(requestHeaders, 'origin')) requestHeaders.origin = origin;
        requestHeaders['x-seo-csrf'] = '1';
      }
    }
    if (bearer) requestHeaders.authorization = `Bearer ${bearer === true ? token : bearer}`;
    if (cookie) requestHeaders.cookie = cookie;
    const response = await runtime.dispatchFetch(`${requestOrigin}${path}`, {
      method,
      headers: requestHeaders,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const raw = await response.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = raw; }
    assert.equal(response.status, expectedStatus, `${method} ${path}: ${JSON.stringify(data)}`);
    checks += 1;
    return { response, data };
  }

  async function beginRegistration({ bearer = true, label = 'Synthetic security key', ...requestOptions } = {}) {
    const result = await request('/auth/register/options', { method: 'POST', body: { label }, bearer, ...requestOptions });
    assert.equal(result.data.options.rp.id, new URL(origin).hostname);
    assert.equal(result.data.options.authenticatorSelection.userVerification, 'required');
    assert.equal(result.data.options.authenticatorSelection.residentKey, 'required');
    assert.equal(result.data.options.attestation, 'none');
    assert.ok(result.data.options.pubKeyCredParams.some((value) => value.alg === -7));
    assert.ok(result.data.options.pubKeyCredParams.some((value) => value.alg === -257));
    assert.ok(result.data.challengeId);
    const cookie = challengeCookie(result.response);
    for (const attribute of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/']) assert.ok(cookie.header.includes(attribute));
    return { ...result.data, cookie: cookie.pair };
  }

  async function finishRegistration(authenticator, ceremony, { responseOptions, ...requestOptions } = {}) {
    return request('/auth/register/verify', {
      method: 'POST', bearer: true, cookie: ceremony.cookie,
      body: { challengeId: ceremony.challengeId, response: authenticator.registration(ceremony.options, origin, responseOptions) },
      ...requestOptions,
    });
  }

  async function beginLogin(requestOptions = {}) {
    const result = await request('/auth/login/options', { method: 'POST', body: {}, ...requestOptions });
    assert.equal(result.data.options.rpId, new URL(origin).hostname);
    assert.equal(result.data.options.userVerification, 'required');
    assert.ok(!result.data.options.allowCredentials?.length, 'Discoverable login must not enumerate enrolled IDs');
    return { ...result.data, cookie: challengeCookie(result.response).pair };
  }

  async function finishLogin(authenticator, ceremony, { responseOptions, ...requestOptions } = {}) {
    return request('/auth/login/verify', {
      method: 'POST', cookie: ceremony.cookie,
      body: { challengeId: ceremony.challengeId, response: authenticator.authentication(ceremony.options, origin, responseOptions) },
      ...requestOptions,
    });
  }

  async function login(authenticator, responseOptions) {
    const ceremony = await beginLogin();
    const result = await finishLogin(authenticator, ceremony, { responseOptions });
    assert.equal(result.data.authenticated, true);
    return { ...result, cookie: sessionCookie(result.response).pair };
  }

  async function tableCounts() {
    return Promise.all(['auth_passkeys', 'auth_challenges', 'auth_sessions'].map(async (table) => (await db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first()).n));
  }

  assert.deepEqual((await request('/auth/session')).data, { enabled: true, authenticated: false });
  await request('/status', { expectedStatus: 401 });
  await request('/status', { bearer: true });
  const countsBeforeGet = await tableCounts();
  for (const path of ['/auth/login/options', '/auth/login/verify', '/auth/register/options', '/auth/register/verify', '/auth/token', '/auth/logout']) {
    await request(path, { expectedStatus: 405 });
  }
  assert.deepEqual(await tableCounts(), countsBeforeGet, 'GET must not create authentication state');

  await request('/auth/register/options', { method: 'POST', body: {}, expectedStatus: 401 });
  await request('/auth/register/options', { method: 'POST', body: {}, bearer: 'incorrect synthetic token', expectedStatus: 401 });
  await request('/auth/register/options', { method: 'POST', body: {}, bearer: true, csrf: false, expectedStatus: 403 });
  await request('/auth/register/options', { method: 'POST', body: {}, bearer: true, headers: { origin: foreignOrigin }, expectedStatus: 403 });
  await request('/auth/register/options', { method: 'POST', body: {}, bearer: true, headers: { 'content-type': 'text/plain' }, expectedStatus: 415 });
  await request('/auth/login/options', { method: 'POST', body: {}, csrf: false, expectedStatus: 403 });
  await request('/auth/login/options', { method: 'POST', body: {}, requestOrigin: foreignOrigin, expectedStatus: 403 });

  const ec = syntheticAuthenticator();
  const rsa = syntheticAuthenticator({ algorithm: 'RS256' });
  const enrollment = await beginRegistration({ label: 'Synthetic P-256 key' });
  await finishRegistration(ec, enrollment, { bearer: false, expectedStatus: 401 });
  assert.equal((await finishRegistration(ec, enrollment)).data.verified, true);
  await finishRegistration(ec, enrollment, { expectedStatus: 400 });
  assert.equal((await finishRegistration(rsa, await beginRegistration({ label: 'Synthetic RSA key' }))).data.verified, true);
  const keys = (await request('/auth/passkeys', { bearer: true })).data.passkeys;
  assert.equal(keys.length, 2);
  assert.deepEqual(keys.map((key) => key.label).sort(), ['Synthetic P-256 key', 'Synthetic RSA key']);
  assert.ok(keys.every((key) => key.id && key.createdAt));
  await request('/auth/passkeys', { expectedStatus: 401 });

  // New enrollment is bearer-only even if the browser already has a session.
  const tokenSession = await request('/auth/token', { method: 'POST', body: {}, bearer: true });
  const tokenCookie = sessionCookie(tokenSession.response);
  for (const attribute of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', 'Max-Age=28800']) assert.ok(tokenCookie.header.includes(attribute));
  assert.ok(!tokenCookie.header.includes('Domain='));
  assert.equal(tokenSession.response.headers.get('cache-control'), 'private, no-store');
  assert.equal(tokenSession.response.headers.get('access-control-allow-origin'), null);
  assert.equal((await request('/auth/session', { cookie: tokenCookie.pair })).data.authenticated, true);
  await request('/auth/register/options', { method: 'POST', body: {}, cookie: tokenCookie.pair, expectedStatus: 401 });
  const secondEnrollment = await beginRegistration();
  await finishRegistration(syntheticAuthenticator(), secondEnrollment, { bearer: false, cookie: `${secondEnrollment.cookie}; ${tokenCookie.pair}`, expectedStatus: 401 });

  const sessions = (await db.prepare('SELECT * FROM auth_sessions').all()).results;
  assert.ok(sessions.length > 0);
  assert.ok(!JSON.stringify(sessions).includes(tokenCookie.value), 'The raw session bearer secret must never be persisted');
  assert.ok(JSON.stringify(sessions).includes(hash(tokenCookie.value)), 'Persist a SHA-256 session hash');
  await request('/status', { cookie: tokenCookie.pair });
  await request('/proposals', { method: 'POST', body: {}, cookie: tokenCookie.pair, csrf: false, expectedStatus: 401 });
  await request('/proposals', { method: 'POST', body: {}, cookie: tokenCookie.pair, headers: { origin: foreignOrigin }, expectedStatus: 401 });
  await request('/proposals', { method: 'POST', body: {}, cookie: tokenCookie.pair, expectedStatus: 400 });
  await request('/mcp', { method: 'POST', body: {}, cookie: tokenCookie.pair, expectedStatus: 401 });
  await request('/internal/llms.txt', { cookie: tokenCookie.pair, expectedStatus: 401 });
  await request('/status', { cookie: '__Host-seo-session=invalid', expectedStatus: 401 });
  await request('/status', { cookie: `${tokenCookie.pair}; ${tokenCookie.pair}`, expectedStatus: 401 });
  await request('/status', { cookie: tokenCookie.pair, bearer: 'incorrect synthetic token', expectedStatus: 401 });
  await request('/status', { cookie: tokenCookie.pair, requestOrigin: foreignOrigin, expectedStatus: 401 });

  // Both key families verify signatures in the actual Worker crypto runtime.
  const ecLogin = await login(ec);
  await request('/status', { cookie: ecLogin.cookie });
  await login(ec); // Synchronized passkeys legitimately retain a zero counter.
  const rsaLogin = await login(rsa, { counter: 1 });
  await finishLogin(rsa, await beginLogin(), { responseOptions: { counter: 1 }, expectedStatus: 400 });
  await login(rsa, { counter: 2 });

  for (const responseOptions of [
    { flags: 0x01 }, // User presence without user verification.
    { rpId: 'public.example.com' },
    { challenge: randomBytes(32).toString('base64url') },
    { type: 'webauthn.create' },
    { crossOrigin: true },
    { corruptSignature: true },
    { userHandle: randomBytes(32).toString('base64url') },
  ]) {
    await finishLogin(ec, await beginLogin(), { responseOptions, expectedStatus: 400 });
  }
  const foreignLogin = await beginLogin();
  await request('/auth/login/verify', {
    method: 'POST', cookie: foreignLogin.cookie, expectedStatus: 400,
    body: { challengeId: foreignLogin.challengeId, response: ec.authentication(foreignLogin.options, foreignOrigin) },
  });
  const missingCookie = await beginLogin();
  await finishLogin(ec, missingCookie, { cookie: undefined, expectedStatus: 400 });
  const firstChallenge = await beginLogin();
  const otherChallenge = await beginLogin();
  await finishLogin(ec, firstChallenge, { cookie: otherChallenge.cookie, expectedStatus: 400 });
  const used = await beginLogin();
  await finishLogin(ec, used);
  await finishLogin(ec, used, { expectedStatus: 400 });
  const expiredChallenge = await beginLogin();
  await db.prepare('UPDATE auth_challenges SET expires_at = ? WHERE id = ?')
    .bind(Math.floor(Date.now() / 1000) - 1, expiredChallenge.challengeId).run();
  await finishLogin(ec, expiredChallenge, { expectedStatus: 400 });

  const expiredSession = await login(ec);
  const expiredCookie = sessionCookie(expiredSession.response);
  const storedSession = await db.prepare('SELECT created_at, expires_at FROM auth_sessions WHERE token_hash = ?')
    .bind(hash(expiredCookie.value)).first();
  assert.equal(storedSession.expires_at - storedSession.created_at, 8 * 60 * 60);
  await db.prepare('UPDATE auth_sessions SET expires_at = ? WHERE token_hash = ?')
    .bind(Math.floor(Date.now() / 1000) - 1, hash(expiredCookie.value)).run();
  assert.equal((await request('/auth/session', { cookie: expiredCookie.pair })).data.authenticated, false);
  await request('/status', { cookie: expiredCookie.pair, expectedStatus: 401 });

  // The one-use check must be atomic across independently handled requests.
  const concurrent = await beginLogin();
  const concurrentBody = JSON.stringify({ challengeId: concurrent.challengeId, response: ec.authentication(concurrent.options, origin) });
  const concurrentNow = Math.floor(Date.now() / 1000);
  const concurrentBefore = (await db.prepare('SELECT COUNT(*) AS n FROM auth_sessions WHERE expires_at > ?').bind(concurrentNow).first()).n;
  const concurrentResults = await Promise.all([1, 2].map(() => runtime.dispatchFetch(`${origin}/auth/login/verify`, {
    method: 'POST', body: concurrentBody,
    headers: { origin, 'content-type': 'application/json', 'x-seo-csrf': '1', cookie: concurrent.cookie },
  })));
  assert.deepEqual(concurrentResults.map((response) => response.status).sort(), [200, 400]);
  await Promise.all(concurrentResults.map((response) => response.text()));
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM auth_sessions WHERE expires_at > ?').bind(concurrentNow).first()).n, concurrentBefore + 1);

  // Registration also verifies UV, RP ID, client origin and ceremony purpose.
  for (const responseOptions of [
    { flags: 0x41 },
    { rpId: 'public.example.com' },
    { type: 'webauthn.get' },
    { crossOrigin: true },
  ]) await finishRegistration(syntheticAuthenticator(), await beginRegistration(), { responseOptions, expectedStatus: 400 });
  const foreignRegistration = await beginRegistration();
  await request('/auth/register/verify', {
    method: 'POST', bearer: true, cookie: foreignRegistration.cookie, expectedStatus: 400,
    body: { challengeId: foreignRegistration.challengeId, response: syntheticAuthenticator().registration(foreignRegistration.options, foreignOrigin) },
  });
  const wrongPurpose = await beginRegistration();
  await finishLogin(ec, { ...wrongPurpose, options: { ...wrongPurpose.options, rpId: new URL(origin).hostname } }, { expectedStatus: 400 });

  // Logout is a POST protected by the same Origin/CSRF rules as mutations.
  await request('/auth/logout', { cookie: ecLogin.cookie, expectedStatus: 405 });
  await request('/status', { cookie: ecLogin.cookie });
  await request('/auth/logout', { method: 'POST', body: {}, cookie: ecLogin.cookie, csrf: false, expectedStatus: 403 });
  const loggedOut = await request('/auth/logout', { method: 'POST', body: {}, cookie: ecLogin.cookie });
  assert.equal(loggedOut.data.authenticated, false);
  assert.ok(sessionCookie(loggedOut.response).header.includes('Max-Age=0'));
  await request('/status', { cookie: ecLogin.cookie, expectedStatus: 401 });

  // Deleting an enrolled key invalidates its existing browser sessions.
  const rsaKey = keys.find((key) => key.label === 'Synthetic RSA key');
  await request(`/auth/passkeys/${encodeURIComponent(rsaKey.id)}`, { method: 'DELETE', body: {}, cookie: rsaLogin.cookie, expectedStatus: 401 });
  await request(`/auth/passkeys/${encodeURIComponent(rsaKey.id)}`, { method: 'DELETE', body: {}, bearer: true });
  await request('/status', { cookie: rsaLogin.cookie, expectedStatus: 401 });
  await finishLogin(rsa, await beginLogin(), { responseOptions: { counter: 3 }, expectedStatus: 400 });

  // Rotating the root token invalidates old keys, sessions and pending ceremonies.
  const rotationSession = await login(ec);
  const rotationChallenge = await beginLogin();
  const previousToken = token;
  token = randomBytes(32).toString('base64url');
  options.bindings.AGENT_TOKEN = token;
  await runtime.setOptions(options);
  // setOptions replaces Miniflare's proxy objects while preserving D1 data.
  db = await runtime.getD1Database('DB');
  await request('/status', { bearer: previousToken, expectedStatus: 401 });
  await request('/status', { bearer: true });
  await request('/status', { cookie: rotationSession.cookie, expectedStatus: 401 });
  await request('/status', { cookie: tokenCookie.pair, expectedStatus: 401 });
  assert.deepEqual((await request('/auth/passkeys', { bearer: true })).data.passkeys, []);
  await finishLogin(ec, rotationChallenge, { expectedStatus: 400 });
  await finishLogin(ec, await beginLogin(), { expectedStatus: 400 });

  // Browser authentication fails closed if schema/configuration is unavailable;
  // independent bearer automation still reaches the ordinary REST API.
  await db.prepare('DROP TABLE auth_sessions').run();
  await request('/auth/session', { expectedStatus: 503 });
  await request('/status', { bearer: true });
  await request('/auth/token', { method: 'POST', body: {}, bearer: true, expectedStatus: 503 });
  options.bindings.AUTH_ORIGIN = '';
  await runtime.setOptions(options);
  assert.deepEqual((await request('/auth/session')).data, { enabled: false, authenticated: false });
  await request('/auth/login/options', { method: 'POST', body: {}, expectedStatus: 503 });
  await request('/status', { cookie: rotationSession.cookie, expectedStatus: 401 });
  await request('/status', { bearer: true });

  for (const invalidOrigin of ['http://auth.example.com', `${origin}/`, `${origin}/path`, `https://user:password@auth.example.com`]) {
    options.bindings.AUTH_ORIGIN = invalidOrigin;
    await runtime.setOptions(options);
    await request('/auth/session', { expectedStatus: 503 });
    await request('/status', { bearer: true });
  }

  assert.equal(outboundRequests, 0, 'Passkey integration tests must not make outbound requests');
  console.log(`SEO authentication workerd integration passed (${checks} HTTP checks; real D1, P-256 and RSA signatures).`);
} finally {
  if (runtime) await runtime.dispose();
  await rm(stateDir, { recursive: true, force: true });
}
