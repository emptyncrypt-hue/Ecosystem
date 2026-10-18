/**
 * Attach this Worker as a Cloudflare route on dunesub.de and www.dunesub.de.
 * fetch(request) then reaches the DNS-configured Squarespace origin while
 * retaining the public hostname, cookies, method, body, and query string.
 * A workers.dev URL is deliberately not an origin proxy or a site preview.
 * SEO_OVERRIDES must bind the same KV namespace as the agent's OVERRIDES.
 */

const PUBLIC_HOSTS = new Set(['dunesub.de', 'www.dunesub.de']);
export const MAX_HTML_BYTES = 2 * 1024 * 1024;
const PROCESSING_TIMEOUT_MS = 2_000;

/** Read a clone with a limit; cancellation must not wait for its untouched tee. */
async function readBounded(response, signal) {
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  let complete = false;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    signal.throwIfAborted();
    while (true) {
      const { value, done } = await reader.read();
      signal.throwIfAborted();
      if (done) { complete = true; break; }
      length += value.byteLength;
      if (length > MAX_HTML_BYTES) throw new Error('HTML exceeds rewrite limit');
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  } finally {
    signal.removeEventListener('abort', cancel);
    if (!complete) cancel();
    reader.releaseLock();
  }
}

function parseOverride(raw) {
  if (typeof raw !== 'string' || raw.length > MAX_HTML_BYTES) return null;
  const value = JSON.parse(raw);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const title = typeof value.title === 'string' && value.title !== '' ? value.title : undefined;
  const description = typeof value.description === 'string' && value.description !== '' ? value.description : undefined;
  return title === undefined && description === undefined ? null : { title, description };
}

async function rewrite(origin, override, signal, makeRewriter) {
  // Keep the acquired origin response untouched until the entire rewrite has
  // succeeded, including failures that HTMLRewriter reports while streaming.
  // Workers fetch exposes the decoded HTTP body while retaining the origin's
  // encoding headers. Bound that decoded body before constructing a new one.
  const bytes = await readBounded(origin.clone(), signal);
  const inputHeaders = new Headers(origin.headers);
  inputHeaders.delete('content-encoding');
  inputHeaders.delete('content-length');
  const input = new Response(bytes, {
    status: origin.status, statusText: origin.statusText, headers: inputHeaders,
  });
  let changed = false;
  const rewriter = makeRewriter()
    .on('head > title', {
      element(element) {
        if (override.title === undefined) return;
        element.setInnerContent(override.title, { html: false });
        changed = true;
      },
    })
    .on('head meta', {
      element(element) {
        const keys = ['name', 'property'].map(name => (element.getAttribute(name) || '').toLowerCase());
        const isTitle = keys.some(key => key === 'og:title' || key === 'twitter:title');
        const isDescription = keys.some(key => ['description', 'og:description', 'twitter:description'].includes(key));
        const value = isTitle ? override.title : isDescription ? override.description : undefined;
        if (value === undefined || element.getAttribute('content') === value) return;
        element.setAttribute('content', value);
        changed = true;
      },
    });
  const transformed = rewriter.transform(input);
  const body = await readBounded(transformed, signal);
  if (!changed) return origin;

  const headers = new Headers(transformed.headers);
  for (const name of ['etag', 'last-modified', 'content-encoding', 'content-length',
    'content-md5', 'digest', 'content-digest', 'repr-digest', 'accept-ranges']) {
    headers.delete(name);
  }
  // No new representation negotiation: retain the origin's Vary exactly.
  const response = new Response(body, { status: origin.status, statusText: origin.statusText, headers });
  // The replacement is complete; release the buffered fallback tee now.
  void origin.body.cancel().catch(() => {});
  return response;
}

/** Dependencies are injectable for offline tests; production uses fetch(request). */
export async function handleRequest(request, env, {
  fetchImpl = fetch,
  makeRewriter = () => new HTMLRewriter(),
} = {}) {
  const url = new URL(request.url);
  if (!['http:', 'https:'].includes(url.protocol) || !PUBLIC_HOSTS.has(url.host) || url.username || url.password) {
    return new Response('Not found', { status: 404 });
  }

  // Fetch exactly once. Transport failures propagate rather than inventing a
  // successful page or repeating a potentially state-changing request.
  const origin = await fetchImpl(request);
  const type = origin.headers.get('content-type') || '';
  const encoding = (origin.headers.get('content-encoding') || 'identity').trim().toLowerCase();
  const length = Number(origin.headers.get('content-length'));
  if (request.method !== 'GET' || !origin.ok || origin.status === 206 || !origin.body ||
      origin.headers.has('content-range') || !/^\s*text\/html(?:\s*;|\s*$)/i.test(type) ||
      !['identity', 'gzip', 'br'].includes(encoding) ||
      length > MAX_HTML_BYTES) return origin;

  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error('SEO rewrite timed out'));
    }, PROCESSING_TIMEOUT_MS);
  });
  try {
    const work = (async () => {
      const raw = await env.SEO_OVERRIDES.get(`override:${url.pathname}`, { cacheTtl: 300 });
      controller.signal.throwIfAborted();
      const override = parseOverride(raw);
      return override ? rewrite(origin, override, controller.signal, makeRewriter) : origin;
    })();
    return await Promise.race([work, deadline]);
  } catch {
    return origin;
  } finally {
    clearTimeout(timer);
  }
}

