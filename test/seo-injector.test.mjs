import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gzipSync, brotliCompressSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import worker from '../services/seo-injector/src/index.mjs';
import { handleRequest, MAX_HTML_BYTES, MAX_SOCIAL_BYTES, serveSocialImage } from '../services/seo-injector/src/handler.mjs';
import { CANONICAL_HOME, PLATFORM_TITLE, PLATFORM_DESCRIPTION, PLATFORM_CSS_PATH,
  SOCIAL_IMAGE, SOCIAL_IMAGE_KEY, SOCIAL_IMAGE_PATH } from '../services/seo-injector/src/platform.mjs';

const page = '<!doctype html><html><head><title>Origin title</title>' +
  '<meta name="description" content="Origin description">' +
  '<meta property="og:title" content="Origin title">' +
  '<meta name="twitter:title" content="Origin title">' +
  '<meta property="og:description" content="Origin description">' +
  '<meta name="twitter:description" content="Origin description">' +
  '</head><body><svg><title>Accessible name</title></svg><p>Original body</p></body></html>';
const originHeaders = {
  'content-type': 'text/html; charset=utf-8',
  etag: '"original"', 'last-modified': 'Wed, 01 Jan 2025 00:00:00 GMT',
  'content-length': String(Buffer.byteLength(page)), 'content-encoding': 'identity',
  'content-md5': 'original-md5', digest: 'original-digest',
  'content-digest': 'original-content-digest', 'repr-digest': 'original-repr-digest',
  'accept-ranges': 'bytes', vary: 'Accept-Encoding, Cookie',
  'content-security-policy': "default-src 'self'", 'set-cookie': 'session=existing; Secure; HttpOnly',
};
const escapeText = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const escapeAttribute = value => escapeText(value).replaceAll('"', '&quot;');

// This small HTMLRewriter contract double checks selectors and the text-only
// insertion API; production parsing and escaping belong to Cloudflare.
class HTMLRewriterDouble {
  handlers = new Map();
  constructor({ failure } = {}) { this.failure = failure; }
  on(selector, handler) {
    assert.ok(['head > title', 'head meta'].includes(selector));
    this.handlers.set(selector, handler);
    return this;
  }
  transform(response) {
    if (this.failure === 'transform') throw new Error('rewrite setup failed');
    const handlers = this.handlers;
    const failure = this.failure;
    return new Response(new ReadableStream({
      async start(controller) {
        try {
          if (failure === 'stream') {
            controller.enqueue(new TextEncoder().encode('partial rewritten page'));
            controller.error(new Error('asynchronous parser failure'));
            return;
          }
          const source = await response.text();
          const output = source.replace(/(<head\b[^>]*>)([\s\S]*?)(<\/head>)/i, (_, open, head, close) => {
            let result = head.replace(/<title\b[^>]*>[\s\S]*?<\/title>/gi, tag => {
              let replacement;
              handlers.get('head > title')?.element({
                setInnerContent(value, options) {
                  assert.deepEqual(options, { html: false });
                  replacement = `<title>${escapeText(value)}</title>`;
                },
              });
              return replacement ?? tag;
            });
            result = result.replace(/<meta\b[^>]*>/gi, tag => {
              const attributes = new Map();
              for (const match of tag.matchAll(/([\w:-]+)\s*=\s*["']([^"']*)["']/g)) {
                attributes.set(match[1].toLowerCase(), match[2]);
              }
              let changed = false;
              handlers.get('head meta')?.element({
                getAttribute(name) { return attributes.get(name) ?? null; },
                setAttribute(name, value) { attributes.set(name, value); changed = true; },
              });
              return changed ? `<meta ${[...attributes].map(([key, value]) => `${key}="${escapeAttribute(value)}"`).join(' ')}>` : tag;
            });
            return open + result + close;
          });
          controller.enqueue(new TextEncoder().encode(output));
          controller.close();
        } catch (error) { controller.error(error); }
      },
    }), { status: response.status, statusText: response.statusText, headers: response.headers });
  }
}

function fixture({ response, raw = JSON.stringify({ title: 'Approved title' }), kvError, failure } = {}) {
  const origin = response ?? new Response(page, { headers: originHeaders });
  const requests = [];
  const keys = [];
  let rewrites = 0;
  return {
    origin, requests, keys,
    env: { SEO_OVERRIDES: { async get(...args) { keys.push(args); if (kvError) throw kvError; return raw; } } },
    deps: {
      async fetchImpl(request) { requests.push(request); return origin; },
      makeRewriter() { rewrites++; if (failure === 'constructor') throw new Error('no rewriter'); return new HTMLRewriterDouble({ failure }); },
    },
    get rewrites() { return rewrites; },
  };
}

test('injector rejects previews, arbitrary hosts, ports, and forged origin headers without fetching', async () => {
  for (const host of ['dunesub-seo-injector.example.workers.dev', 'example.com', 'dunesub.de.evil.test', 'other.dunesub.de', 'dunesub.de:8443']) {
    const f = fixture();
    const result = await handleRequest(new Request(`https://${host}/`, {
      headers: { 'x-original-host': 'dunesub.de', 'x-forwarded-host': 'dunesub.de' },
    }), f.env, f.deps);
    assert.equal(result.status, 404);
    assert.equal(f.requests.length, 0);
    assert.equal(f.keys.length, 0);
  }
  // The default export also rejects preview traffic without runtime bindings.
  assert.equal((await worker.fetch(new Request('https://preview.workers.dev/'), {})).status, 404);
});

test('both public hosts fetch the original request with URL, query, cookies, and authorization intact', async () => {
  for (const host of ['dunesub.de', 'www.dunesub.de']) {
    const f = fixture({ raw: null });
    const request = new Request(`https://${host}/news/a%2Fb?campaign=a%2Bb&n=2`, {
      headers: { cookie: 'session=private; cart=one', authorization: 'Bearer example', accept: 'text/html' },
    });
    const result = await handleRequest(request, { ...f.env, ORIGIN_HOST: 'unrelated.example' }, f.deps);
    assert.equal(result, f.origin);
    assert.deepEqual(f.requests, [request]);
    assert.equal(f.requests[0].url, request.url);
    assert.equal(f.requests[0].headers.get('cookie'), 'session=private; cart=one');
    assert.equal(f.requests[0].headers.get('authorization'), 'Bearer example');
    assert.deepEqual(f.keys, [['override:/news/a%2Fb', { cacheTtl: 300 }]]);
    assert.equal(f.rewrites, 0);
  }
});

test('state-changing methods preserve the same request and body and never consult KV', async () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    const f = fixture();
    const request = new Request('https://dunesub.de/form?return=%2Fcart', {
      method, body: 'name=Alice&quantity=2',
      headers: { cookie: 'cart=one', 'content-type': 'application/x-www-form-urlencoded' },
    });
    f.deps.fetchImpl = async received => {
      f.requests.push(received);
      assert.equal(received, request);
      assert.equal(received.method, method);
      assert.equal(received.url, request.url);
      assert.equal(received.headers.get('cookie'), 'cart=one');
      assert.equal(await received.text(), 'name=Alice&quantity=2');
      return f.origin;
    };
    assert.equal(await handleRequest(request, f.env, f.deps), f.origin);
    assert.equal(f.requests.length, 1);
    assert.equal(f.keys.length, 0);
    assert.equal(f.rewrites, 0);
  }
});

test('origin transport failure propagates after one fetch even if the POST body was consumed', async () => {
  const request = new Request('https://dunesub.de/checkout', { method: 'POST', body: 'order=one' });
  const failure = new Error('origin transport unavailable');
  let calls = 0;
  await assert.rejects(handleRequest(request, {}, {
    async fetchImpl(received) { calls++; assert.equal(await received.text(), 'order=one'); throw failure; },
  }), error => error === failure);
  assert.equal(calls, 1);
});

test('redirects, errors, partial content and non-HTML pass through without KV or header changes', async () => {
  const cases = [
    { status: 301, headers: { location: 'https://www.dunesub.de/new' } },
    { status: 302 }, { status: 304 }, { status: 401 }, { status: 403 },
    { status: 404 }, { status: 500 }, { status: 206 }, { status: 204 },
    { type: 'application/json' }, { type: 'text/htmlish' }, { type: 'application/not-text/html' },
    { headers: { 'content-range': 'bytes 0-100/1000' } },
  ];
  for (const input of cases) {
    const status = input.status ?? 200;
    const response = new Response([204, 304].includes(status) ? null : page, {
      status, headers: { ...originHeaders, 'content-type': input.type ?? originHeaders['content-type'], ...input.headers },
    });
    const before = [...response.headers];
    const f = fixture({ response });
    assert.equal(await handleRequest(new Request('https://dunesub.de/', { method: input.method ?? 'GET' }), f.env, f.deps), response);
    assert.deepEqual([...response.headers], before);
    assert.equal(f.keys.length, 0);
    assert.equal(f.rewrites, 0);
  }
});

test('missing, malformed, and non-string override fields retain the original response and validators', async () => {
  for (const raw of [null, '', '{bad json', 'null', '[]', '7', '"text"', '{}',
    '{"title":7,"description":false}', '{"title":"","description":""}', '{"redirect":"https://example.com"}']) {
    const f = fixture({ raw });
    const result = await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps);
    assert.equal(result, f.origin);
    assert.equal(result.headers.get('etag'), '"original"');
    assert.equal(await result.text(), page);
    assert.equal(f.rewrites, 0);
    assert.equal(f.requests.length, 1);
  }
});

test('KV failure serves the acquired origin body unchanged without another fetch', async () => {
  const f = fixture({ kvError: new Error('KV unavailable') });
  const result = await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps);
  assert.equal(result, f.origin);
  assert.equal(await result.text(), page);
  assert.equal(f.requests.length, 1);
  assert.equal(f.rewrites, 0);
});

test('approved title and description replace existing head tags using escaped text and attributes', async () => {
  const title = 'Approved <script>bad()</script> & "quoted"';
  const description = 'Description " onload="bad() <img src=x> & more';
  const response = new Response(page, { status: 201, statusText: 'Created', headers: originHeaders });
  const f = fixture({ response, raw: JSON.stringify({ title, description, redirect: 'https://evil.test', h1: 'ignored' }) });
  const result = await handleRequest(new Request('https://dunesub.de/article?preview=one'), f.env, f.deps);
  const html = await result.text();
  assert.ok(html.includes(`<title>${escapeText(title)}</title>`));
  assert.equal(html.split(`content="${escapeAttribute(title)}"`).length - 1, 2);
  assert.equal(html.split(`content="${escapeAttribute(description)}"`).length - 1, 3);
  assert.ok(html.includes('<svg><title>Accessible name</title></svg>'));
  assert.ok(html.includes('<p>Original body</p>'));
  assert.ok(!html.includes('<script>bad()'));
  assert.ok(!html.includes('https://evil.test'));
  assert.equal(result.status, 201);
  assert.equal(result.statusText, 'Created');
  assert.equal(result.headers.get('vary'), originHeaders.vary);
  assert.equal(result.headers.get('set-cookie'), originHeaders['set-cookie']);
  assert.equal(result.headers.get('content-security-policy'), originHeaders['content-security-policy']);
  for (const header of ['etag', 'last-modified', 'content-length', 'content-encoding', 'content-md5',
    'digest', 'content-digest', 'repr-digest', 'accept-ranges']) assert.equal(result.headers.get(header), null, header);
  assert.equal(f.origin.headers.get('etag'), '"original"');
  assert.equal(f.requests.length, 1);
  assert.deepEqual(f.keys, [['override:/article', { cacheTtl: 300 }]]);
});

test('a single valid field is applied while invalid fields and unrelated tags stay unchanged', async () => {
  const f = fixture({ raw: JSON.stringify({ title: 42, description: 'Only approved description' }) });
  const html = await (await handleRequest(new Request('https://www.dunesub.de/article'), f.env, f.deps)).text();
  assert.ok(html.includes('<title>Origin title</title>'));
  assert.ok(html.includes('property="og:title" content="Origin title"'));
  assert.equal(html.split('content="Only approved description"').length - 1, 3);
});

test('decoded gzip and Brotli fetch bodies receive approved metadata without stale encoding headers', async () => {
  for (const [encoding, compress] of [['gzip', gzipSync], ['br', brotliCompressSync]]) {
    const compressed = compress(page);
    // Match Workers fetch: decoded body with original HTTP encoding headers.
    const response = new Response(page, { headers: {
      ...originHeaders, 'content-encoding': encoding, 'content-length': String(compressed.length),
    } });
    const f = fixture({ response });
    const result = await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps);
    assert.ok((await result.text()).includes('<title>Approved title</title>'));
    assert.equal(result.headers.get('content-encoding'), null);
    assert.equal(result.headers.get('content-length'), null);
    assert.equal(f.requests.length, 1);
  }
});

test('unsupported content encodings pass through without interpreting their bytes', async () => {
  const response = new Response('encoded-origin-body', { headers: { ...originHeaders, 'content-encoding': 'unknown' } });
  const f = fixture({ response });
  assert.equal(await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps), response);
  assert.equal(await response.text(), 'encoded-origin-body');
  assert.equal(f.keys.length, 0);
  assert.equal(f.requests.length, 1);
});

test('decompressed HTML beyond the limit keeps the original compressed response intact', async () => {
  const decoded = '<title>Large page</title>' + 'x'.repeat(MAX_HTML_BYTES);
  const compressed = gzipSync(decoded);
  const response = new Response(decoded, { headers: {
    ...originHeaders, 'content-encoding': 'gzip', 'content-length': String(compressed.length),
  } });
  const f = fixture({ response });
  assert.equal(await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps), response);
  assert.equal(response.headers.get('content-encoding'), 'gzip');
  assert.equal(await response.text(), decoded);
  assert.equal(f.requests.length, 1);
});

test('overrides never add absent tags and keep validators when no existing tag is changed', async () => {
  for (const html of ['<html><head></head><body><svg><title>Body title</title></svg></body></html>',
    '<html><head><meta name="description" content="Already approved"></head></html>']) {
    const f = fixture({ response: new Response(html, { headers: originHeaders }), raw: '{"description":"Already approved"}' });
    const result = await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps);
    assert.equal(result, f.origin);
    assert.equal(result.headers.get('etag'), '"original"');
    assert.equal(result.headers.get('content-encoding'), 'identity');
    assert.equal(await result.text(), html);
  }
});

test('rewriter setup and asynchronous streaming failures retain the original body after one fetch', async () => {
  for (const failure of ['constructor', 'transform', 'stream']) {
    const f = fixture({ failure });
    const result = await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps);
    assert.equal(result, f.origin);
    assert.equal(result.headers.get('etag'), '"original"');
    assert.equal(await result.text(), page);
    assert.equal(f.requests.length, 1);
  }
});

test('HTML rewrite input is bounded with and without Content-Length', async () => {
  const html = 'x'.repeat(MAX_HTML_BYTES + 1);
  for (const known of [true, false]) {
    const headers = { 'content-type': 'text/html', etag: '"large"' };
    if (known) headers['content-length'] = String(Buffer.byteLength(html));
    const f = fixture({ response: new Response(html, { headers }) });
    const result = await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps);
    assert.equal(result, f.origin);
    assert.equal(result.headers.get('etag'), '"large"');
    assert.equal((await result.text()).length, html.length);
    assert.equal(f.requests.length, 1);
    assert.equal(f.keys.length, known ? 0 : 1);
    assert.equal(f.rewrites, 0);
  }
});

test('a stalled rewrite clone times out and leaves the original stream available', { timeout: 5_000 }, async () => {
  let cancelled = false;
  const bytes = new TextEncoder().encode('<html><head><title>Slow');
  const response = new Response(new ReadableStream({
    start(controller) { controller.enqueue(bytes); },
    cancel() { cancelled = true; },
  }), { headers: { 'content-type': 'text/html', etag: '"slow"' } });
  const f = fixture({ response });
  const result = await handleRequest(new Request('https://dunesub.de/article'), f.env, f.deps);
  assert.equal(result, response);
  assert.equal(result.headers.get('etag'), '"slow"');
  assert.equal(f.requests.length, 1);
  const reader = result.body.getReader();
  assert.deepEqual((await reader.read()).value, bytes);
  await reader.cancel();
  assert.equal(cancelled, true);
});

test('all homepage aliases render the approved platform and consult only the canonical override key', async () => {
  for (const path of ['/', '/home', '/home/']) {
    const f = fixture({ raw: null });
    const result = await handleRequest(new Request(`https://www.dunesub.de${path}?utm_source=example`), f.env, f.deps);
    const html = await result.text();
    assert.ok(html.includes(`<title>${escapeText(PLATFORM_TITLE)}</title>`));
    assert.ok(html.includes(`<meta name="description" content="${PLATFORM_DESCRIPTION}">`));
    assert.ok(html.includes(`<link rel="canonical" href="${CANONICAL_HOME}">`));
    assert.ok(html.includes(`content="https://www.dunesub.de${SOCIAL_IMAGE_PATH}"`));
    assert.ok(html.includes(`content="${SOCIAL_IMAGE.width}"`));
    assert.ok(html.includes('name="twitter:card" content="summary_large_image"'));
    assert.ok(html.includes('Validate payloads against policy'));
    assert.ok(html.includes('pinned source, provenance checks'));
    assert.ok(!html.includes('Original body'));
    assert.ok(!html.includes('Your Site Title'));
    assert.ok(!html.includes('<script'));
    assert.ok(!html.includes('<style'));
    assert.ok(!/TPM|PKCS|enclave|immutable request tracing/i.test(html));
    assert.deepEqual(f.keys, [['override:/', { cacheTtl: 300 }]]);
    assert.equal(f.requests.length, 1);
    assert.equal(f.rewrites, 0);
    for (const header of ['etag', 'last-modified', 'content-length', 'content-encoding', 'content-md5',
      'digest', 'content-digest', 'repr-digest', 'accept-ranges']) assert.equal(result.headers.get(header), null);
    for (const name of ['vary', 'content-security-policy', 'set-cookie']) assert.equal(result.headers.get(name), originHeaders[name]);
    assert.equal(result.headers.get('link'), `<${CANONICAL_HOME}>; rel="canonical"`);
  }
});

test('canonical homepage approvals are escaped consistently and stale alias approvals cannot replace platform copy', async () => {
  for (const canonical of [null, '{bad json', JSON.stringify({ title: PLATFORM_TITLE, description: PLATFORM_DESCRIPTION })]) {
    const f = fixture();
    f.env.SEO_OVERRIDES.get = async key => {
      f.keys.push(key);
      return key === 'override:/' ? canonical : JSON.stringify({ description: 'Generic blogging services' });
    };
    const html = await (await handleRequest(new Request('https://www.dunesub.de/home'), f.env, f.deps)).text();
    assert.ok(html.includes(PLATFORM_DESCRIPTION));
    assert.ok(!html.includes('Generic blogging services'));
    assert.deepEqual(f.keys, ['override:/']);
  }
  const f = fixture({ raw: JSON.stringify({ title: 'Approved <unsafe> title', description: 'Approved "quote" & description' }) });
  const html = await (await handleRequest(new Request('https://www.dunesub.de/'), f.env, f.deps)).text();
  assert.ok(html.includes('<title>Approved &lt;unsafe&gt; title</title>'));
  assert.equal(html.split('Approved &quot;quote&quot; &amp; description').length - 1, 3);
  assert.ok(!html.includes('<unsafe>'));
});

test('homepage editing, alternate formats, authentication and privacy gates preserve the origin', async () => {
  for (const input of [
    { query: '?format=json' }, { query: '?preview=true' }, { query: '?view=editor' },
    { headers: { accept: 'application/json' } }, { headers: { authorization: 'Bearer private' } },
    { headers: { range: 'bytes=0-100' } }, { headers: { 'x-requested-with': 'XMLHttpRequest' } },
  ]) {
    const f = fixture();
    const result = await handleRequest(new Request(`https://www.dunesub.de/${input.query ?? ''}`, { headers: input.headers }), f.env, f.deps);
    assert.equal(result, f.origin);
    assert.equal(f.keys.length, 0);
    assert.equal(f.requests.length, 1);
  }
  for (const input of [
    { html: '<html><body class="sqs-password-page">Private site</body></html>' },
    { html: '<html><head><meta name="robots" content="noindex,nofollow"></head><body>Private</body></html>' },
    { html: '<html><head><meta name="robots" content="none"></head><body>Private</body></html>' },
    { html: '<html><head><meta content=noindex name=robots></head><body>Private</body></html>' },
    { html: '<html><head><meta NAME=googlebot CONTENT="NONE"></head><body>Private</body></html>' },
    { html: page, headers: { 'x-robots-tag': 'noindex' } },
    { html: page, headers: { 'x-robots-tag': 'googlebot: none' } },
  ]) {
    const f = fixture({ raw: null, response: new Response(input.html, { headers: { ...originHeaders, ...input.headers } }) });
    const result = await handleRequest(new Request('https://www.dunesub.de/'), f.env, f.deps);
    assert.equal(result, f.origin);
    assert.equal(await result.text(), input.html);
    assert.equal(f.requests.length, 1);
  }
});

test('conditional controlled requests acquire one fresh origin response while other requests retain validators', async () => {
  for (const path of ['/', '/home', '/sitemap.xml', '/article', '/?preview=true', '/sitemap.xml?format=xml']) {
    const controlled = ['/', '/home', '/sitemap.xml'].includes(path);
    const request = new Request('https://www.dunesub.de' + path, { headers: {
      'if-none-match': '"old-origin"', 'if-modified-since': 'Wed, 01 Jan 2025 00:00:00 GMT', cookie: 'visitor=one',
    } });
    const f = fixture({ response: new Response(page, { headers: originHeaders }) });
    f.deps.fetchImpl = async received => {
      f.requests.push(received);
      assert.equal(received.method, 'GET');
      assert.equal(received.url, request.url);
      assert.equal(received.headers.get('cookie'), 'visitor=one');
      assert.equal(received.headers.has('if-none-match'), !controlled);
      assert.equal(received.headers.has('if-modified-since'), !controlled);
      if (!controlled) assert.equal(received, request);
      return f.origin;
    };
    await handleRequest(request, f.env, f.deps);
    assert.equal(f.requests.length, 1);
  }
});

test('controlled HEAD omits origin body validators and size without GET replay or bypassing private status', async () => {
  for (const path of ['/', '/home', '/sitemap.xml', '/article']) {
    const f = fixture({ response: new Response(null, { headers: {
      ...originHeaders, 'content-length': '123', 'content-type': path === '/sitemap.xml' ? 'application/xml' : 'text/html',
    } }) });
    const response = await handleRequest(new Request('https://www.dunesub.de' + path, { method: 'HEAD' }), f.env, f.deps);
    assert.equal(f.requests.length, 1);
    assert.equal(f.requests[0].method, 'HEAD');
    assert.equal(f.keys.length, 0);
    assert.equal(response.headers.get('content-security-policy'), originHeaders['content-security-policy']);
    assert.equal(response.headers.get('etag'), path === '/article' ? '"original"' : null);
    assert.equal(response.headers.get('content-length'), path === '/article' ? '123' : null);
    assert.equal(await response.text(), '');
  }
  const f = fixture({ response: new Response(null, { status: 401, headers: originHeaders }) });
  assert.equal(await handleRequest(new Request('https://www.dunesub.de/', { method: 'HEAD' }), f.env, f.deps), f.origin);
});

test('sitemap canonicalization changes existing known-alias locations without inventing or accepting unrelated pages', async () => {
  const input = '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' +
    '<url><loc>https://sepia-carnation-yj5e.squarespace.com/home</loc><lastmod>2026-10-18</lastmod></url>' +
    '<url><loc>https://www.dunesub.de/home/</loc></url>' +
    '<url><loc>https://dunesub.de/</loc></url>' +
    '<url><loc>https://sepia-carnation-yj5e.squarespace.com/about?x=one&amp;y=two</loc></url>' +
    '<url><loc>https://unrelated.squarespace.com/home</loc></url>' +
    '<url><loc>https://www.dunesub.de/other</loc></url>' +
    '<url><loc>https://www.dunesub.de.evil.test/home</loc></url></urlset>';
  const headers = { ...originHeaders, 'content-type': 'application/xml; charset=utf-8' };
  const f = fixture({ response: new Response(input, { headers }) });
  const result = await handleRequest(new Request('https://www.dunesub.de/sitemap.xml'), f.env, f.deps);
  const xml = await result.text();
  assert.equal(xml.split(`<loc>${CANONICAL_HOME}</loc>`).length - 1, 3);
  assert.ok(xml.includes('<loc>https://www.dunesub.de/about?x=one&amp;y=two</loc>'));
  assert.ok(xml.includes('<lastmod>2026-10-18</lastmod>'));
  assert.ok(xml.includes('<loc>https://unrelated.squarespace.com/home</loc>'));
  assert.ok(xml.includes('<loc>https://www.dunesub.de/other</loc>'));
  assert.ok(xml.includes('<loc>https://www.dunesub.de.evil.test/home</loc>'));
  assert.equal((xml.match(/<url>/g) ?? []).length, 7);
  assert.equal(f.requests.length, 1);
  assert.equal(f.keys.length, 0);
  assert.equal(result.headers.get('content-type'), headers['content-type']);
  assert.equal(result.headers.get('etag'), null);
  assert.equal(result.headers.get('content-encoding'), null);
});

test('unmodified sitemap, non-sitemap XML, private sitemap and failed XML decoding retain the origin', async () => {
  const cases = [
    { path: '/sitemap.xml', body: `<urlset><url><loc>${CANONICAL_HOME}</loc></url></urlset>` },
    { path: '/other.xml', body: '<loc>https://sepia-carnation-yj5e.squarespace.com/home</loc>' },
    { path: '/sitemap.xml', body: '<loc>https://sepia-carnation-yj5e.squarespace.com/home</loc>', status: 401 },
    { path: '/sitemap.xml', body: Uint8Array.of(0xff, 0xfe) },
  ];
  for (const input of cases) {
    const response = new Response(input.body, { status: input.status ?? 200, headers: { 'content-type': 'text/xml', etag: '"unchanged"' } });
    const f = fixture({ response });
    assert.equal(await handleRequest(new Request(`https://www.dunesub.de${input.path}`), f.env, f.deps), response);
    assert.equal(response.headers.get('etag'), '"unchanged"');
    assert.equal(f.keys.length, 0);
    assert.equal(f.requests.length, 1);
  }
});

test('controlled CSS and exact versioned social asset paths respect GET and HEAD and preserve unrelated assets', async () => {
  for (const method of ['GET', 'HEAD']) {
    const f = fixture({ raw: null });
    const css = await handleRequest(new Request(`https://www.dunesub.de${PLATFORM_CSS_PATH}`, { method }), f.env, f.deps);
    assert.equal(css.status, 200);
    assert.match(css.headers.get('content-type'), /^text\/css/);
    const body = await css.text();
    assert.equal(method === 'GET' ? body.includes('prefers-reduced-motion') : body === '', true);
    assert.equal(f.requests.length, 0);
    const missingImage = await handleRequest(new Request(`https://www.dunesub.de${SOCIAL_IMAGE_PATH}`, { method }), f.env, f.deps);
    assert.equal(missingImage.status, 404);
    assert.equal(missingImage.headers.get('cache-control'), 'no-store');
    assert.deepEqual(f.keys.at(-1), [SOCIAL_IMAGE_KEY, { type: 'arrayBuffer', cacheTtl: 86_400 }]);
    assert.equal(f.requests.length, 0);
  }
  for (const path of ['/__dunesub/social/unrelated.png', '/images/site.png', '/favicon.ico']) {
    const f = fixture({ raw: null, response: new Response('original asset', { headers: { 'content-type': 'image/png' } }) });
    assert.equal(await handleRequest(new Request(`https://www.dunesub.de${path}`), f.env, f.deps), f.origin);
    assert.equal(f.requests.length, 1);
    assert.equal(f.keys.length, 0);
  }
});

test('social asset serving verifies PNG dimensions and content hash before immutable GET/HEAD responses', async () => {
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a1ZkAAAAASUVORK5CYII=', 'base64');
  const bytes = png.buffer.slice(png.byteOffset, png.byteOffset + png.byteLength);
  const image = { width: 1, height: 1, sha256: createHash('sha256').update(png).digest('hex') };
  for (const method of ['GET', 'HEAD']) {
    const calls = [];
    const env = { SEO_OVERRIDES: { async get(...args) { calls.push(args); return bytes; } } };
    const response = await serveSocialImage(new Request('https://www.dunesub.de/image.png', { method }), env, new AbortController().signal, image);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'image/png');
    assert.equal(response.headers.get('content-length'), String(png.byteLength));
    assert.equal(response.headers.get('cache-control'), 'public, max-age=31536000, immutable');
    assert.equal(response.headers.get('etag'), `"${image.sha256}"`);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), method === 'HEAD' ? Buffer.alloc(0) : png);
    assert.deepEqual(calls, [[`asset:dunesub-social:${image.sha256}.png`, { type: 'arrayBuffer', cacheTtl: 86_400 }]]);
  }
  for (const input of [null, new ArrayBuffer(MAX_SOCIAL_BYTES + 1), new ArrayBuffer(24),
    { bytes, image: { ...image, width: 2 } }, { bytes, image: { ...image, sha256: '0'.repeat(64) } }]) {
    const response = await serveSocialImage(new Request('https://www.dunesub.de/image.png'),
      { SEO_OVERRIDES: { async get() { return input?.bytes ?? input; } } }, new AbortController().signal, input?.image ?? image);
    assert.equal(response.status, 404);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  }
});
