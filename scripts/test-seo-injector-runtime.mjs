import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { CANONICAL_HOME, PLATFORM_TITLE, PLATFORM_DESCRIPTION, PLATFORM_CSS_PATH } from '../services/seo-injector/src/platform.mjs';

// This smoke check uses workerd's real HTMLRewriter and local KV. Every origin
// fetch is intercepted below: it cannot contact Squarespace or another host.
const serviceUrl = new URL('../services/seo-agent/', import.meta.url);
const require = createRequire(new URL('package.json', serviceUrl));
const { Miniflare, Log, LogLevel } = require('miniflare');
const { build } = require('esbuild');
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
// A tiny valid PNG keeps the native asset test hermetic. The same production
// handler and metadata renderer are bundled with this test-only manifest.
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a1ZkAAAAASUVORK5CYII=', 'base64');
const testImage = { width: 1, height: 1, sha256: createHash('sha256').update(png).digest('hex'), alt: 'DuneSub Ecosystem test image' };
const testImagePath = `/__dunesub/social/${testImage.sha256}.png`;
// Match Wrangler's production bundle, including the nonsecret JSON manifest.
const bundled = (await build({
  entryPoints: [fileURLToPath(new URL('../services/seo-injector/src/index.mjs', import.meta.url))],
  bundle: true, format: 'esm', platform: 'neutral', write: false,
  plugins: [{ name: 'fixture-social-image', setup(build) {
    build.onLoad({ filter: /social-image\.json$/ }, () => ({ loader: 'json', contents: JSON.stringify(testImage) }));
  } }],
})).outputFiles[0].text;

const runtime = new Miniflare({
  modules: [{ type: 'ESModule', path: fileURLToPath(new URL('../services/seo-injector/src/index.mjs', import.meta.url)), contents: bundled }],
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
    } else if (path === '/sitemap.xml') {
      const xml = '<urlset><url><loc>https://sepia-carnation-yj5e.squarespace.com/home</loc></url>' +
        '<url><loc>https://unrelated.squarespace.com/home</loc></url></urlset>';
      const bytes = gzipSync(xml);
      response.writeHead(200, { ...headers, 'content-type': 'application/xml', 'content-length': String(bytes.length) });
      response.end(bytes);
    } else {
      const encoding = path === '/deflate' ? 'deflate' : path === '/brotli' ? 'br' : 'gzip';
      const bytes = encoding === 'deflate' ? deflateSync(html) : encoding === 'br' ? brotliCompressSync(html) : compressed;
      response.writeHead(path === '/private' || url.searchParams.has('private') ? 401 : 200, {
        ...headers, 'content-encoding': encoding, 'content-length': String(bytes.length),
      });
      response.end(bytes);
    }
  } },
});

try {
  const kv = await runtime.getKVNamespace('SEO_OVERRIDES');
  await kv.put(`asset:dunesub-social:${testImage.sha256}.png`, png);
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

  for (const path of ['/', '/home', '/home/']) {
    const response = await runtime.dispatchFetch(`https://www.dunesub.de${path}`);
    const body = await response.text();
    assert.ok(body.includes(`<title>${PLATFORM_TITLE.replaceAll('&', '&amp;')}</title>`));
    assert.ok(body.includes(`<meta name="description" content="${PLATFORM_DESCRIPTION}">`));
    assert.ok(body.includes(`<link rel="canonical" href="${CANONICAL_HOME}">`));
    assert.ok(body.includes(`content="https://www.dunesub.de${testImagePath}"`));
    assert.ok(body.includes('Validate payloads against policy'));
    assert.ok(!body.includes('Original body'));
    assert.equal(response.headers.get('etag'), null);
    for (const name of ['vary', 'content-security-policy', 'set-cookie']) assert.equal(response.headers.get(name), headers[name]);
    assert.equal(response.headers.get('link'), `<${CANONICAL_HOME}>; rel="canonical"`);
  }
  assert.equal(calls.length, 10);

  const gatedHome = await runtime.dispatchFetch('https://www.dunesub.de/?private=true');
  assert.equal(gatedHome.status, 401);
  assert.equal(await gatedHome.text(), html);
  assert.equal(gatedHome.headers.get('etag'), '"origin"');
  const editingHome = await runtime.dispatchFetch('https://www.dunesub.de/home?preview=true');
  assert.equal(await editingHome.text(), html);
  assert.equal(editingHome.headers.get('etag'), '"origin"');
  assert.equal(calls.length, 12);

  const sitemap = await runtime.dispatchFetch('https://www.dunesub.de/sitemap.xml');
  const xml = await sitemap.text();
  assert.ok(xml.includes(`<loc>${CANONICAL_HOME}</loc>`));
  assert.ok(!xml.includes('sepia-carnation-yj5e'));
  assert.ok(xml.includes('<loc>https://unrelated.squarespace.com/home</loc>'));
  assert.equal(sitemap.headers.get('etag'), null);
  assert.equal(sitemap.headers.get('content-encoding'), null);
  assert.equal(calls.length, 13);

  for (const method of ['GET', 'HEAD']) {
    const css = await runtime.dispatchFetch(`https://www.dunesub.de${PLATFORM_CSS_PATH}`, { method });
    assert.equal(css.status, 200);
    assert.match(css.headers.get('content-type'), /^text\/css/);
    const cssBody = await css.text();
    assert.equal(method === 'GET' ? cssBody.includes('prefers-reduced-motion') : cssBody === '', true);
    const image = await runtime.dispatchFetch(`https://www.dunesub.de${testImagePath}`, { method });
    assert.equal(image.status, 200);
    assert.equal(image.headers.get('content-type'), 'image/png');
    assert.equal(image.headers.get('cache-control'), 'public, max-age=31536000, immutable');
    assert.equal(image.headers.get('etag'), `"${testImage.sha256}"`);
    assert.deepEqual(Buffer.from(await image.arrayBuffer()), method === 'HEAD' ? Buffer.alloc(0) : png);
  }
  assert.equal(calls.length, 13, 'controlled assets must not contact Squarespace');
  console.log('SEO injector workerd smoke passed: platform aliases, canonical sitemap, versioned PNG/CSS, compressed metadata, privacy/CSP/cookies, and one-fetch forms.');
} finally {
  await runtime.dispose();
}
