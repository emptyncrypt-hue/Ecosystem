/**
 * A private document, separate from the site's optional public /llms.txt.
 * The two secret bindings are never sent to the crawler, AI, D1, or shared KV.
 */
export const INTERNAL_LLMS_PATH = '/internal/llms.txt';
const MAX_PLAINTEXT_BYTES = 2048;
const MAX_ENVELOPE_CHARS = 4096;

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
