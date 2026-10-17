import test from 'node:test';
import assert from 'node:assert/strict';
import { createSeoAgentClient, SeoAgentError } from '../src/lib/seo-agent.mjs';

const options = { url: 'https://seo.example.test', token: 'synthetic-test-token' };
const status = { running: false, lastRun: null, openFindingsBySeverity: [], proposalsByStatus: [], config: {} };
const analytics = {
  gsc: { active: false, daily: [] }, aeo: { daily: [], weekly: [], topBots7d: [] },
  citations: { active: false, series: [] }, findings: { series: [] }, changes: [],
};

function mockTransport(replies) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, ...init });
    assert.ok(replies.length, 'unexpected request');
    const next = replies.shift();
    if (next instanceof Error) throw next;
    return next instanceof Response ? next : Response.json(next.body, { status: next.status ?? 200 });
  };
  return { calls, fetchImpl };
}

function errorCode(code, expectedStatus) {
  return (error) => {
    assert.ok(error instanceof SeoAgentError);
    assert.equal(error.code, code);
    if (expectedStatus !== undefined) assert.equal(error.status, expectedStatus);
    return true;
  };
}

test('read methods use the deployed routes and authenticated requests without redirects', async () => {
  const bodies = [status, [], [], [], [], analytics];
  const transport = mockTransport(bodies.map((body) => ({ body })));
  const client = createSeoAgentClient({ ...options, fetchImpl: transport.fetchImpl });
  const results = await Promise.all([client.status(), client.findings(), client.proposals(), client.changes(), client.overrides(), client.analytics()]);
  assert.deepEqual(results, bodies);
  assert.deepEqual(transport.calls.map((call) => call.url), [
    '/status', '/findings?status=open', '/proposals?status=proposed', '/changes', '/overrides', '/analytics/summary',
  ].map((route) => `${options.url}${route}`));
  for (const call of transport.calls) {
    assert.equal(call.method, 'GET');
    assert.equal(call.headers.Authorization, `Bearer ${options.token}`);
    assert.equal(call.headers.Accept, 'application/json');
    assert.equal(call.redirect, 'error');
    assert.ok(call.signal instanceof AbortSignal);
    assert.equal(call.body, undefined);
  }
});

test('filters accept only upstream lifecycle statuses; invalid arguments never request the network', async () => {
  const transport = mockTransport(Array.from({ length: 7 }, () => ({ body: [] })));
  const client = createSeoAgentClient({ ...options, fetchImpl: transport.fetchImpl });
  for (const value of ['open', 'resolved', 'dismissed']) await client.findings(value);
  for (const value of ['proposed', 'approved', 'rejected', 'reverted']) await client.proposals(value);
  for (const value of ['', 'all', 'OPEN', 'open&token=bad', null, 1, {}]) {
    assert.throws(() => client.findings(value), errorCode('input'));
    assert.throws(() => client.proposals(value), errorCode('input'));
  }
  for (const value of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '1', '1/revert', null, undefined]) {
    for (const method of ['approve', 'reject', 'revert']) assert.throws(() => client[method](value), errorCode('input'));
  }
  assert.equal(transport.calls.length, 7);
});

test('populated lists preserve upstream fields and serialized override values', async () => {
  const bodies = [
    [{ id: 1, path: '/', rule: 'missing_description', severity: 'high', status: 'open', remediation: null, draftable: true }],
    [{ id: 2, path: '/', field: 'description', proposed_value: 'A description', current_value: null, status: 'proposed', model: 'example' }],
    [{ id: 3, path: '/', field: 'description', old_value: null, new_value: 'A description', reverted_at: null }],
    [{ key: 'override:/', value: '{"description":"A description"}' }, { key: 'override:/removed', value: null }],
  ];
  const transport = mockTransport(bodies.map((body) => ({ body })));
  const client = createSeoAgentClient({ ...options, fetchImpl: transport.fetchImpl });
  assert.deepEqual([await client.findings(), await client.proposals(), await client.changes(), await client.overrides()], bodies);
});

test('writes use upstream endpoints once, accept asynchronous run and confirm decision IDs', async () => {
  const bodies = [
    { started: true, running: true }, { ok: true, id: 12, status: 'approved', changeId: 8 },
    { ok: true, id: 13, status: 'rejected' }, { ok: true },
  ];
  const transport = mockTransport(bodies.map((body, index) => ({ body, status: index === 0 ? 202 : 200 })));
  const client = createSeoAgentClient({ ...options, fetchImpl: transport.fetchImpl });
  assert.deepEqual([await client.run(), await client.approve(12), await client.reject(13), await client.revert(8)], bodies);
  assert.deepEqual(transport.calls.map(({ url, method }) => ({ url, method })), [
    '/run', '/proposals/12/approve', '/proposals/13/reject', '/changes/8/revert',
  ].map((route) => ({ url: `${options.url}${route}`, method: 'POST' })));
});

test('a busy run is a useful typed 409 error and is never retried', async () => {
  const transport = mockTransport([{ status: 409, body: { started: false, running: true } }]);
  const client = createSeoAgentClient({ ...options, fetchImpl: transport.fetchImpl });
  await assert.rejects(client.run(), (error) => {
    errorCode('busy', 409)(error);
    assert.match(error.message, /already in progress/);
    return true;
  });
  assert.equal(transport.calls.length, 1);
});

test('origin validation rejects paths, redirects through userinfo, insecure remote hosts and hidden delimiters', () => {
  const values = [
    '', null, 'seo.example.test', 'ftp://seo.example.test', 'http://seo.example.test', 'http://0.0.0.0:8787',
    'https://user:password@seo.example.test', 'https://@seo.example.test', 'https://seo.example.test/api',
    'https://seo.example.test/foo/..', 'https://seo.example.test/%2f', 'https://seo.example.test?token=bad',
    'https://seo.example.test?', 'https://seo.example.test#', ' https://seo.example.test',
    'https://seo.example.test\n', 'https://seo.example.test\\', 'http://localhost.example.test',
    'http://127.0.0.1.example.test', 'http://127.1:8787', 'https://',
  ];
  for (const url of values) assert.throws(() => createSeoAgentClient({ ...options, url }), errorCode('config'));
});

test('HTTPS origins and explicit loopback HTTP origins work, with trailing slash normalized', async () => {
  for (const url of ['https://seo.example.test/', 'https://seo.example.test:8443', 'http://localhost:8787/', 'http://127.0.0.1:8787', 'http://[::1]:8787']) {
    const transport = mockTransport([{ body: status }]);
    await createSeoAgentClient({ ...options, url, fetchImpl: transport.fetchImpl }).status();
    assert.equal(transport.calls[0].url, `${new URL(url).origin}/status`);
  }
});

test('invalid token, timeout and fetch configuration fail before a request', () => {
  for (const token of ['', '  ', null, 'bad\rvalue', 'bad\nvalue']) {
    assert.throws(() => createSeoAgentClient({ ...options, token }), errorCode('config'));
  }
  for (const timeoutMs of [0, -1, 0.5, NaN, Infinity, '1000', 2_147_483_648]) {
    assert.throws(() => createSeoAgentClient({ ...options, timeoutMs }), errorCode('config'));
  }
  assert.throws(() => createSeoAgentClient({ ...options, fetchImpl: null }), errorCode('config'));
});

test('HTTP and transport failures never echo remote bodies, URLs or bearer credentials', async () => {
  for (const httpStatus of [301, 401, 403, 404, 409, 429, 500]) {
    const transport = mockTransport([{ status: httpStatus, body: { error: `${options.token} confidential remote body` } }]);
    const client = createSeoAgentClient({ ...options, fetchImpl: transport.fetchImpl });
    await assert.rejects(client.approve(1), (error) => {
      errorCode('http', httpStatus)(error);
      assert.ok(!JSON.stringify(error).includes(options.token));
      assert.ok(!error.stack.includes(options.token));
      assert.ok(!error.message.includes('confidential'));
      assert.ok(!error.message.includes(options.url));
      return true;
    });
    assert.equal(transport.calls.length, 1);
  }
  const transport = mockTransport([new Error(`redirect or connection error ${options.url} ${options.token}`)]);
  await assert.rejects(createSeoAgentClient({ ...options, fetchImpl: transport.fetchImpl }).status(), (error) => {
    errorCode('network')(error);
    assert.ok(!error.stack.includes(options.token));
    assert.equal(error.cause, undefined);
    return true;
  });
});

test('timeout aborts the request, returns promptly and does not retry a write', async () => {
  let calls = 0;
  let signal;
  const client = createSeoAgentClient({ ...options, timeoutMs: 15, fetchImpl: async (url, init) => {
    calls++;
    signal = init.signal;
    return new Promise(() => {});
  } });
  await assert.rejects(client.run(), errorCode('timeout'));
  assert.equal(signal.aborted, true);
  assert.equal(calls, 1);
});

test('timeout also bounds receiving a response body', async () => {
  let canceled = false;
  const body = new ReadableStream({ start() {}, cancel() { canceled = true; } });
  const client = createSeoAgentClient({ ...options, timeoutMs: 15, fetchImpl: async () => new Response(body) });
  await assert.rejects(client.status(), errorCode('timeout'));
  assert.equal(canceled, true);
});

test('streamed bodies are bounded even without Content-Length and are canceled on overflow', async () => {
  let canceled = false;
  const oversized = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(600_000));
      controller.enqueue(new Uint8Array(600_000));
    },
    cancel() { canceled = true; },
  });
  const client = createSeoAgentClient({ ...options, fetchImpl: async () => new Response(oversized) });
  await assert.rejects(client.status(), (error) => {
    errorCode('response')(error);
    assert.match(error.message, /1 MiB/);
    return true;
  });
  assert.equal(canceled, true);
});

test('oversized declared bodies are rejected without reading', async () => {
  let canceled = false;
  const body = new ReadableStream({ start() {}, cancel() { canceled = true; } });
  const response = new Response(body, { headers: { 'Content-Length': '1048577' } });
  await assert.rejects(createSeoAgentClient({ ...options, fetchImpl: async () => response }).status(), errorCode('response'));
  assert.equal(canceled, true);
});

test('bounded valid multibyte JSON is read across byte boundaries', async () => {
  const value = [{ key: 'override:/🌍:title', value: 'Hello 🌍' }];
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const body = new ReadableStream({ start(controller) {
    for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
    controller.close();
  } });
  const client = createSeoAgentClient({ ...options, fetchImpl: async () => new Response(body) });
  assert.deepEqual(await client.overrides(), value);
});

test('malformed JSON, invalid UTF-8 and wrong response shapes fail cleanly', async () => {
  for (const response of [new Response('{'), new Response(new Uint8Array([0xff])), Response.json(null), Response.json({ error: 'oops' })]) {
    await assert.rejects(createSeoAgentClient({ ...options, fetchImpl: async () => response }).status(), errorCode('response'));
  }
  const wrongBodies = [
    ['findings', [{ id: 1, path: '/', rule: 'missing_title', severity: 'high', status: 'unknown' }]],
    ['proposals', [{ id: 1, path: '/', field: 'title', status: 'proposed' }]],
    ['changes', [{ id: -1, path: '/', field: 'title' }]],
    ['overrides', [{ key: 'override:/', value: {} }]],
    ['analytics', {}], ['run', { started: false, running: true }],
  ];
  for (const [method, body] of wrongBodies) {
    await assert.rejects(createSeoAgentClient({ ...options, fetchImpl: async () => Response.json(body) })[method](), errorCode('response'));
  }
  for (const [method, body] of [
    ['approve', { ok: true, id: 2, status: 'approved', changeId: 3 }],
    ['reject', { ok: true, id: 1, status: 'approved' }], ['revert', { ok: false }],
  ]) {
    await assert.rejects(createSeoAgentClient({ ...options, fetchImpl: async () => Response.json(body) })[method](1), errorCode('response'));
  }
});
