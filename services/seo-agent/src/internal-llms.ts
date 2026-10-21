/**
 * A private document, separate from the site's optional public /llms.txt.
 * Provider secrets are never sent to the crawler, AI, D1, or shared KV.
 */
export const INTERNAL_LLMS_PATH = '/internal/llms.txt';
const MAX_PLAINTEXT_BYTES = 2048;
const MAX_ENVELOPE_CHARS = 4096;
const BRIDGE_TIMEOUT_MS = 10_000;

/** Used for every private-route response, including authentication failures. */
export function internalLlmsResponse(request: Request, status: number, body: string, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('Content-Type', 'text/plain; charset=utf-8');
  headers.set('Cache-Control', 'private, no-store');
  headers.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
  headers.set('Vary', 'Authorization');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Content-Security-Policy', "default-src 'none'");
  return new Response(request.method === 'HEAD' ? null : body, { status, headers });
}

function decodeBase64url(value: unknown, minBytes: number, maxBytes: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid encoding');
  // Bound allocation before decoding untrusted configuration.
  if (value.length > Math.ceil(maxBytes * 4 / 3)) throw new Error('invalid length');
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const canonical = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (canonical !== value || bytes.length < minBytes || bytes.length > maxBytes) throw new Error('invalid encoding');
  return bytes;
}

/** The key ID pins enrollment; it is not remote hardware attestation. */
async function readYubikeyBridge(request: Request, env: Env, siteOrigin: string): Promise<Response> {
  const bridgeUrl = env.INTERNAL_LLMS_BRIDGE_URL;
  if (!bridgeUrl || bridgeUrl.length > 512) throw new Error('invalid bridge');
  const bridge = new URL(bridgeUrl);
  const hostname = bridge.hostname;
  if (bridge.protocol !== 'https:' || bridge.port || bridge.username || bridge.password ||
      env.INTERNAL_LLMS_BRIDGE_URL !== `${bridge.origin}${INTERNAL_LLMS_PATH}` ||
      !hostname.includes('.') || hostname.length > 253 ||
      !hostname.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
      /^(?:\d+\.){3}\d+$/.test(hostname) || /\.(?:localhost|local|internal)$/.test(hostname) ||
      bridge.origin === siteOrigin || bridge.origin === new URL(request.url).origin) {
    throw new Error('invalid bridge');
  }
  const token = env.INTERNAL_LLMS_BRIDGE_TOKEN;
  const keyId = env.INTERNAL_LLMS_BRIDGE_KEY_ID;
  if (!token || token.length !== 43 || token === env.AGENT_TOKEN ||
      !keyId || !/^sha256:[a-f0-9]{64}$/.test(keyId)) throw new Error('invalid bridge credentials');
  decodeBase64url(token, 32, 32).fill(0);

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new Error('bridge timeout')); }, BRIDGE_TIMEOUT_MS);
  });
  let upstream: Response | undefined;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let complete = false;
  try {
    upstream = await Promise.race([fetch(bridge.href, {
      // workerd supports manual/follow, not the browser's error mode. Refuse
      // every non-200 response below so credentials never follow a redirect.
      method: request.method, redirect: 'manual', signal: controller.signal,
      headers: { Authorization: `Bearer ${token}`, Accept: 'text/plain', 'Cache-Control': 'no-store' },
    }), deadline]);
    const mediaType = upstream.headers.get('content-type') || '';
    const length = upstream.headers.get('content-length');
    if (upstream.status !== 200 || upstream.redirected ||
        !/^text\/plain(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(mediaType) ||
        upstream.headers.get('x-internal-llms-key-id') !== keyId ||
        (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_PLAINTEXT_BYTES))) {
      throw new Error('invalid bridge response');
    }
    if (request.method === 'HEAD') {
      // The bridge checks device enrollment and slot metadata for HEAD without
      // invoking its private key. Do not turn health checks into decryptions.
      return internalLlmsResponse(request, 200, '');
    }
    if (!upstream.body) throw new Error('empty bridge response');
    reader = upstream.body.getReader();
    const plaintext = new Uint8Array(MAX_PLAINTEXT_BYTES);
    let size = 0;
    try {
      while (true) {
        const chunk = await Promise.race([reader.read(), deadline]);
        if (chunk.done) break;
        if (size + chunk.value.byteLength > MAX_PLAINTEXT_BYTES) throw new Error('oversized document');
        plaintext.set(chunk.value, size);
        size += chunk.value.byteLength;
      }
      complete = true;
      reader.releaseLock();
      if (!size || (length !== null && Number(length) !== size)) throw new Error('invalid document size');
      const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext.subarray(0, size));
      if (content.includes('\0')) throw new Error('invalid document');
      return internalLlmsResponse(request, 200, content);
    } finally {
      plaintext.fill(0);
    }
  } finally {
    clearTimeout(timer!);
    if (!complete) {
      controller.abort();
      // Cancellation is best effort; waiting for a stalled source would defeat
      // the deadline. Neither branch logs upstream errors or secret material.
      try { void (reader ? reader.cancel() : upstream?.body?.cancel())?.catch(() => {}); } catch {}
    }
  }
}

/** The caller must pass the existing AGENT_TOKEN authorization gate first. */
export async function handleInternalLlms(request: Request, env: Env): Promise<Response> {
  if (new URL(request.url).protocol !== 'https:') return internalLlmsResponse(request, 403, 'Forbidden\n');
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return internalLlmsResponse(request, 405, 'Method not allowed\n', { Allow: 'GET, HEAD' });
  }

  try {
    const site = new URL(env.SITE_URL);
    if (site.protocol !== 'https:' || site.username || site.password || site.pathname !== '/' || site.search || site.hash) {
      throw new Error('invalid site');
    }
    const provider = env.INTERNAL_LLMS_PROVIDER ?? 'software';
    if (provider === 'yubikey-piv') return await readYubikeyBridge(request, env, site.origin);
    if (provider !== 'software') throw new Error('invalid provider');
    if (!env.INTERNAL_LLMS_KEY || env.INTERNAL_LLMS_KEY.length !== 43 || env.INTERNAL_LLMS_KEY === env.AGENT_TOKEN ||
        !env.INTERNAL_LLMS_CIPHERTEXT || env.INTERNAL_LLMS_CIPHERTEXT.length > MAX_ENVELOPE_CHARS) {
      throw new Error('unconfigured document');
    }
    const envelope: unknown = JSON.parse(env.INTERNAL_LLMS_CIPHERTEXT);
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new Error('invalid envelope');
    const record = envelope as Record<string, unknown>;
    if (Object.keys(record).sort().join(',') !== 'algorithm,ciphertext,nonce,version' ||
        record.version !== 1 || record.algorithm !== 'AES-256-GCM') throw new Error('invalid envelope');

    const keyBytes = decodeBase64url(env.INTERNAL_LLMS_KEY, 32, 32);
    try {
      const nonce = decodeBase64url(record.nonce, 12, 12);
      const ciphertext = decodeBase64url(record.ciphertext, 17, MAX_PLAINTEXT_BYTES + 16);
      const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
      const plaintext = new Uint8Array(await crypto.subtle.decrypt({
        name: 'AES-GCM', iv: nonce, tagLength: 128,
        additionalData: new TextEncoder().encode(`dunesub-internal-llms:v1\n${site.origin}\n${INTERNAL_LLMS_PATH}`),
      }, key, ciphertext));
      try {
        if (!plaintext.length || plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error('invalid document');
        const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
        if (content.includes('\0')) throw new Error('invalid document');
        return internalLlmsResponse(request, 200, content);
      } finally {
        plaintext.fill(0);
      }
    } finally {
      keyBytes.fill(0);
    }
  } catch {
    // Keep missing, corrupt, tampered, and wrong-key configurations indistinguishable.
    // In particular, never log an exception carrying document or binding values.
    return internalLlmsResponse(request, 503, 'Internal document unavailable\n');
  }
}
