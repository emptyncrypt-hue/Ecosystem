/**
 * Attach this Worker as a Cloudflare route on dunesub.de and www.dunesub.de.
 * fetch(request) then reaches the DNS-configured Squarespace origin while
 * retaining the public hostname, cookies, method, body, and query string.
 * A workers.dev URL is deliberately not an origin proxy or a site preview.
 * SEO_OVERRIDES must bind the same KV namespace as the agent's OVERRIDES.
 */

import {
  CANONICAL_HOME, PLATFORM_CSS, PLATFORM_CSS_PATH, SOCIAL_IMAGE,
  SOCIAL_IMAGE_KEY, SOCIAL_IMAGE_PATH, renderPlatform,
} from './platform.mjs';

const PUBLIC_HOSTS = new Set(['dunesub.de', 'www.dunesub.de']);
const HOMEPAGE_PATHS = new Set(['/', '/home', '/home/']);
const PRIVATE_LLM_PATHS = new Set(['/llms.txt', '/llms-full.txt', '/internal/llms.txt']);
const MAX_BOUNDARY_PATH_LENGTH = 8_192;
const SQUARESPACE_ALIAS = 'sepia-carnation-yj5e.squarespace.com';
export const MAX_HTML_BYTES = 2 * 1024 * 1024;
export const MAX_SOCIAL_BYTES = 2 * 1024 * 1024;
const PROCESSING_TIMEOUT_MS = 2_000;

function isPrivateLlmsPath(pathname) {
  // Decode once with a bounded input. The URL parser has already normalized
  // ordinary dot segments; normalize decoded separators/dots as well without
  // interpreting decoded query/fragment characters as a different URL.
  if (pathname.length > MAX_BOUNDARY_PATH_LENGTH) return false;
  let decoded;
  try { decoded = decodeURIComponent(pathname); } catch { return false; }
  const segments = [];
  for (const segment of decoded.replaceAll('\\', '/').split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') segments.pop();
    else segments.push(segment.toLowerCase());
  }
  return PRIVATE_LLM_PATHS.has(`/${segments.join('/')}`);
}

function privateLlmsNotFound(request) {
  // This edge has no private-document binding or decryption key. Never forward
  // credentials to Squarespace, inspect a request body, or consult shared KV.
  return new Response(request.method === 'HEAD' ? null : 'Not found', {
    status: 404,
    headers: {
      'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store',
      'x-robots-tag': 'noindex, nofollow, noarchive', 'x-content-type-options': 'nosniff',
    },
  });
}

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
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const title = typeof value.title === 'string' && value.title !== '' ? value.title : undefined;
  const description = typeof value.description === 'string' && value.description !== '' ? value.description : undefined;
  return title === undefined && description === undefined ? null : { title, description };
}

function representationHeaders(origin) {
  const headers = new Headers(origin.headers);
  for (const name of ['etag', 'last-modified', 'content-encoding', 'content-length',
    'content-md5', 'digest', 'content-digest', 'repr-digest', 'accept-ranges']) {
    headers.delete(name);
  }
  return headers;
}

function replacement(origin, body, extraHeaders = {}) {
  const headers = representationHeaders(origin);
  for (const [name, value] of Object.entries(extraHeaders)) headers.set(name, value);
  const response = new Response(body, { status: origin.status, statusText: origin.statusText, headers });
  void origin.body.cancel().catch(() => {});
  return response;
}

function hasOriginOnlyContext(request, url) {
  if (request.headers.has('authorization') || request.headers.has('range') ||
      request.headers.has('x-requested-with')) return true;
  // Squarespace editing, preview, authentication and alternate-format requests
  // retain the acquired origin representation even when it happens to be HTML.
  for (const key of url.searchParams.keys()) {
    if (/^(?:format|view|editing|preview|password|authenticate|authenticated|sqs.*)$/i.test(key)) return true;
  }
  return false;
}

function isNormalHomepage(request, url) {
  if (!HOMEPAGE_PATHS.has(url.pathname) || hasOriginOnlyContext(request, url)) return false;
  const accept = request.headers.get('accept');
  return !accept || /(?:^|[,\s])(?:text\/html|\*\/\*)(?:[;,\s]|$)/i.test(accept);
}

function hasPrivacyGate(origin, html) {
  const blocksIndexing = value => /(?:^|[,\s:])(?:noindex|none)(?=[,\s;]|$)/i.test(value || '');
  if (blocksIndexing(origin.headers.get('x-robots-tag'))) return true;
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    const attributes = new Map();
    for (const match of tag.matchAll(/\s([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
      if (!attributes.has(match[1].toLowerCase())) attributes.set(match[1].toLowerCase(), match[2] ?? match[3] ?? match[4] ?? '');
    }
    if (/^(?:robots|googlebot)$/i.test(attributes.get('name') || '') && blocksIndexing(attributes.get('content'))) return true;
  }
  return /<(?:body|form|main|div)\b[^>]*\b(?:id|class)\s*=\s*["'][^"']*(?:sqs-password|password-page|site-password)/i.test(html);
}

function canonicalLinkHeader(origin) {
  // Preserve preload and other relations while replacing a prior canonical.
  const entries = (origin.headers.get('link') || '').split(/,(?=\s*<)/)
    .filter(value => value.trim() && !/;\s*rel\s*=\s*(?:["'][^"']*\bcanonical\b[^"']*["']|canonical\b)/i.test(value));
  return [...entries, `<${CANONICAL_HOME}>; rel="canonical"`].join(', ');
}

async function platformHomepage(origin, override, signal) {
  const bytes = await readBounded(origin.clone(), signal);
  const html = new TextDecoder().decode(bytes);
  if (hasPrivacyGate(origin, html)) return origin;
  const body = renderPlatform(override ?? {});
  if (new TextEncoder().encode(body).byteLength > MAX_HTML_BYTES) throw new Error('Platform output exceeds limit');
  return replacement(origin, body, {
    'content-type': 'text/html; charset=utf-8',
    link: canonicalLinkHeader(origin),
  });
}

function canonicalLocation(value) {
  const trimmed = value.trim();
  // Decode only XML's predefined entities; no DTD or external entity handling.
  const decoded = trimmed.replace(/&(amp|lt|gt|quot|apos);/g, (_, name) =>
    ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" })[name]);
  let url;
  try { url = new URL(decoded); } catch { return value; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port ||
      (!PUBLIC_HOSTS.has(url.hostname) && url.hostname !== SQUARESPACE_ALIAS)) return value;
  if (HOMEPAGE_PATHS.has(url.pathname)) return CANONICAL_HOME;
  if (url.hostname !== SQUARESPACE_ALIAS) return value;
  url.protocol = 'https:';
  url.hostname = 'www.dunesub.de';
  return url.href.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&apos;');
}

async function canonicalSitemap(origin, signal) {
  const bytes = await readBounded(origin.clone(), signal);
  const input = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  // Rewriting existing <loc> values does not invent pages or broaden crawler
  // trust. Unknown domains, query structure and all non-location XML survive.
  const output = input.replace(/(<loc\s*>)([^<]*)(<\/loc\s*>)/g,
    (_, open, value, close) => open + canonicalLocation(value) + close);
  if (output === input) return origin;
  if (new TextEncoder().encode(output).byteLength > MAX_HTML_BYTES) throw new Error('Sitemap output exceeds limit');
  return replacement(origin, output);
}

export async function serveSocialImage(request, env, signal, image = SOCIAL_IMAGE) {
  const notFound = () => new Response(request.method === 'HEAD' ? null : 'Not found', {
    status: 404, headers: { 'cache-control': 'no-store' },
  });
  const key = image === SOCIAL_IMAGE ? SOCIAL_IMAGE_KEY : `asset:dunesub-social:${image.sha256}.png`;
  const bytes = await env.SEO_OVERRIDES.get(key, { type: 'arrayBuffer', cacheTtl: 86_400 });
  signal.throwIfAborted();
  if (!(bytes instanceof ArrayBuffer) || bytes.byteLength < 24 || bytes.byteLength > MAX_SOCIAL_BYTES) {
    return notFound();
  }
  const view = new DataView(bytes);
  const signature = new Uint8Array(bytes, 0, 8);
  if (![137, 80, 78, 71, 13, 10, 26, 10].every((byte, index) => signature[index] === byte) ||
      view.getUint32(12) !== 0x49484452 || view.getUint32(16) !== image.width || view.getUint32(20) !== image.height) {
    return notFound();
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const sha = [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
  signal.throwIfAborted();
  if (sha !== image.sha256) return notFound();
  return new Response(request.method === 'HEAD' ? null : bytes, { headers: {
    'content-type': 'image/png', 'content-length': String(bytes.byteLength),
    'cache-control': 'public, max-age=31536000, immutable',
    'x-content-type-options': 'nosniff', etag: `"${sha}"`,
  } });
}

async function bounded(work, fallback) {
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error('SEO rewrite timed out'));
    }, PROCESSING_TIMEOUT_MS);
  });
  try { return await Promise.race([work(controller.signal), deadline]); }
  catch { return fallback(); }
  finally { clearTimeout(timer); }
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

  // No new representation negotiation: retain the origin's Vary exactly.
  return replacement(origin, body);
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

  // Private llms.txt is available only on the authenticated control Worker.
  // Public routes deny every method, including authenticated requests, before
  // any origin fetch or public override/asset lookup can occur.
  if (isPrivateLlmsPath(url.pathname)) return privateLlmsNotFound(request);

  // These two controlled public assets are independent of Squarespace content.
  // Other methods and paths still reach the origin exactly once.
  if (['GET', 'HEAD'].includes(request.method) && url.pathname === PLATFORM_CSS_PATH) {
    return new Response(request.method === 'HEAD' ? null : PLATFORM_CSS, { headers: {
      'content-type': 'text/css; charset=utf-8', 'cache-control': 'public, max-age=3600',
      'x-content-type-options': 'nosniff',
    } });
  }
  if (['GET', 'HEAD'].includes(request.method) && url.pathname === SOCIAL_IMAGE_PATH) {
    return bounded(signal => serveSocialImage(request, env, signal), () =>
      new Response(request.method === 'HEAD' ? null : 'Temporarily unavailable', { status: 503, headers: { 'cache-control': 'no-store' } }));
  }

  // Fetch exactly once. Transport failures propagate rather than inventing a
  // successful page or repeating a potentially state-changing request.
  const readMethod = ['GET', 'HEAD'].includes(request.method);
  const controlledHomepage = readMethod && isNormalHomepage(request, url);
  const controlledSitemap = readMethod && url.pathname === '/sitemap.xml' &&
    !hasOriginOnlyContext(request, url);
  let originRequest = request;
  if (controlledHomepage || controlledSitemap) {
    // An unchanged Squarespace validator cannot validate a changed edge body.
    // Acquire the representation once so returning visitors see the new page.
    const headers = new Headers(request.headers);
    headers.delete('if-none-match');
    headers.delete('if-modified-since');
    originRequest = new Request(request, { headers });
  }
  const origin = await fetchImpl(originRequest);
  const type = origin.headers.get('content-type') || '';
  const encoding = (origin.headers.get('content-encoding') || 'identity').trim().toLowerCase();
  const length = Number(origin.headers.get('content-length'));
  const sitemap = url.pathname === '/sitemap.xml' && /^\s*(?:application|text)\/xml(?:\s*;|\s*$)/i.test(type);
  const html = /^\s*text\/html(?:\s*;|\s*$)/i.test(type);
  if (request.method === 'HEAD' && origin.ok && origin.status !== 206 && !origin.headers.has('content-range') &&
      ((controlledHomepage && html) || (controlledSitemap && sitemap))) {
    // No body is fetched or invented for HEAD. Omit Squarespace's body-specific
    // validators and size because the corresponding edge GET can differ.
    return new Response(null, { status: origin.status, statusText: origin.statusText, headers: representationHeaders(origin) });
  }
  if (request.method !== 'GET' || !origin.ok || origin.status === 206 || !origin.body ||
      origin.headers.has('content-range') || (!html && !sitemap) ||
      !['identity', 'gzip', 'br'].includes(encoding) ||
      length > MAX_HTML_BYTES) return origin;

  // Never replace an editing, preview or alternate-format homepage response.
  if (HOMEPAGE_PATHS.has(url.pathname) && !isNormalHomepage(request, url)) return origin;
  if (sitemap && !controlledSitemap) return origin;
  return bounded(async signal => {
    if (sitemap) return canonicalSitemap(origin, signal);
    const homepage = HOMEPAGE_PATHS.has(url.pathname);
    const raw = await env.SEO_OVERRIDES.get(`override:${homepage ? '/' : url.pathname}`, { cacheTtl: 300 });
    signal.throwIfAborted();
    const override = parseOverride(raw);
    if (homepage) return platformHomepage(origin, override, signal);
    return override ? rewrite(origin, override, signal, makeRewriter) : origin;
  }, () => origin);
}

