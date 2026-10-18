import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib';

// This smoke check uses workerd's real HTMLRewriter and local KV. Every origin
// fetch is intercepted below: it cannot contact Squarespace or another host.
const serviceUrl = new URL('../services/seo-agent/', import.meta.url);
const require = createRequire(new URL('package.json', serviceUrl));
const { Miniflare, Log, LogLevel } = require('miniflare');
const html = '<!doctype html><html><head><title>Origin title</title>' +
  '<meta name="description" content="Origin description">' +
  '<meta property="og:title" content="Origin title">' +
  '<meta name="twitter:title" content="Origin title">' +
  '<meta property="og:description" content="Origin description">' +
  '<meta name="twitter:description" content="Origin description">' +
  '</head><body><svg><title>Accessible name</title></svg><p>Original body</p></body></html>';
const compressed = gzipSync(html);
const title = '<script>unsafe()</script> & "approved"';
const description = 'Dune "quoted" & <description>';
const calls = [];
const headers = {
  'content-type': 'text/html; charset=utf-8', 'content-encoding': 'gzip',
  'content-length': String(compressed.length), etag: '"origin"',
  'last-modified': 'Wed, 01 Jan 2025 00:00:00 GMT', vary: 'Accept-Encoding, Cookie',
  'content-security-policy': "default-src 'self'", 'set-cookie': 'session=kept; Secure; HttpOnly',
};

const runtime = new Miniflare({
  modules: ['index.mjs', 'handler.mjs'].map(name => ({
    type: 'ESModule', path: fileURLToPath(new URL(`../services/seo-injector/src/${name}`, import.meta.url)),
  })),
  compatibilityDate: '2025-06-17',
  log: new Log(LogLevel.ERROR),
  cachePersist: false,
  kvNamespaces: ['SEO_OVERRIDES'],
  // The raw Node service writes gzip bytes exactly once. Miniflare's higher-
  // level Response service automatically compresses bodies and would otherwise
  // double-compress a pre-encoded fixture.
  outboundService: { node: async (request, response) => {
    const url = new URL(request.headers['mf-original-url'] || request.url, `https://${request.headers.host}`);
    assert.ok(['dunesub.de', 'www.dunesub.de'].includes(url.hostname));
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const call = { url: url.href, method: request.method, cookie: request.headers.cookie ?? null, body: Buffer.concat(chunks).toString('utf8') };
    calls.push(call);
    const path = url.pathname;
    if (path === '/form') {
      response.writeHead(200, { 'content-type': 'text/html', etag: '"form"' });
      response.end(JSON.stringify(call));
    } else if (path === '/redirect') {
      response.writeHead(302, { location: 'https://www.dunesub.de/new' });
      response.end();
    } else {
      const encoding = path === '/deflate' ? 'deflate' : path === '/brotli' ? 'br' : 'gzip';
      const bytes = encoding === 'deflate' ? deflateSync(html) : encoding === 'br' ? brotliCompressSync(html) : compressed;
      response.writeHead(path === '/private' ? 401 : 200, {
        ...headers, 'content-encoding': encoding, 'content-length': String(bytes.length),
      });
      response.end(bytes);
    }
  } },
});

try {
  const kv = await runtime.getKVNamespace('SEO_OVERRIDES');
  for (const path of ['/approved', '/private', '/redirect', '/form', '/deflate', '/brotli']) {
    await kv.put(`override:${path}`, JSON.stringify({ title, description }));
  }

  const rewritten = await runtime.dispatchFetch('https://dunesub.de/approved?campaign=a%2Bb', { headers: { cookie: 'session=visitor' } });
  const rewrittenHtml = await rewritten.text();
  assert.equal(rewritten.status, 200);
  assert.ok(rewrittenHtml.includes('<title>&lt;script&gt;unsafe()&lt;/script&gt; &amp; "approved"</title>'), rewrittenHtml);
  assert.ok(rewrittenHtml.includes('&quot;quoted&quot;'));
  // Native HTMLRewriter may retain angle brackets inside quoted attributes;
  // the escaped title above and escaped attribute quotes establish safe insertion.
  assert.ok(!rewrittenHtml.includes('content="Dune "quoted"'));
  assert.ok(rewrittenHtml.includes('<svg><title>Accessible name</title></svg>'));
  assert.ok(rewrittenHtml.includes('<p>Original body</p>'));
  for (const name of ['etag', 'last-modified', 'content-encoding', 'content-length']) assert.equal(rewritten.headers.get(name), null, name);
  for (const name of ['vary', 'content-security-policy', 'set-cookie']) assert.equal(rewritten.headers.get(name), headers[name]);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { url: 'https://dunesub.de/approved?campaign=a%2Bb', method: 'GET', cookie: 'session=visitor', body: '' });

  const plain = await runtime.dispatchFetch('https://www.dunesub.de/plain');
  assert.equal(await plain.text(), html);
  assert.equal(plain.headers.get('etag'), '"origin"');
  assert.equal(plain.headers.get('content-security-policy'), headers['content-security-policy']);
  assert.equal(calls.length, 2);

  const privatePage = await runtime.dispatchFetch('https://dunesub.de/private');
  assert.equal(privatePage.status, 401);
  assert.equal(await privatePage.text(), html);
  assert.equal(privatePage.headers.get('etag'), '"origin"');
  assert.equal(calls.length, 3);

  const redirect = await runtime.dispatchFetch('https://dunesub.de/redirect', { redirect: 'manual' });
  assert.equal(redirect.status, 302);
  assert.equal(redirect.headers.get('location'), 'https://www.dunesub.de/new');
  assert.equal(calls.length, 4);

  const form = await runtime.dispatchFetch('https://www.dunesub.de/form?return=%2Fcart', {
    method: 'POST', body: 'name=Alice&quantity=2',
    headers: { cookie: 'cart=one', 'content-type': 'application/x-www-form-urlencoded' },
  });
  assert.deepEqual(await form.json(), {
    url: 'https://www.dunesub.de/form?return=%2Fcart', method: 'POST', cookie: 'cart=one', body: 'name=Alice&quantity=2',
  });
  assert.equal(form.headers.get('etag'), '"form"');
  assert.equal(calls.length, 5);

  for (const path of ['/deflate', '/brotli']) {
    const response = await runtime.dispatchFetch(`https://dunesub.de${path}`);
    assert.equal(response.status, 200);
    const body = await response.text();
    if (path === '/deflate') {
      assert.equal(body, html);
      assert.equal(response.headers.get('etag'), '"origin"');
    } else {
      assert.ok(body.includes('<title>&lt;script&gt;unsafe()&lt;/script&gt; &amp; "approved"</title>'), `${path}: ${body}`);
      assert.equal(response.headers.get('etag'), null);
    }
  }
  assert.equal(calls.length, 7);

  const preview = await runtime.dispatchFetch('https://preview.workers.dev/approved');
  assert.equal(preview.status, 404);
  assert.equal(calls.length, 7);
  console.log('SEO injector workerd smoke passed: compressed HTML, escaping, cookies/CSP, passthrough, and one-fetch form handling.');
} finally {
  await runtime.dispose();
}
