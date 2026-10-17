import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Execute the bundled Worker in workerd, with real local D1 and KV bindings.
// Nothing in this smoke check starts a crawl, schedules work, or calls AI.
const serviceUrl = new URL('../services/seo-agent/', import.meta.url);
const serviceRequire = createRequire(new URL('package.json', serviceUrl));
const { Miniflare, Log, LogLevel } = serviceRequire('miniflare');
const workerPath = fileURLToPath(new URL('dist/index.js', serviceUrl));
await readFile(workerPath); // Fail before starting workerd if the build is absent.

const stateDir = await mkdtemp(join(tmpdir(), 'ecosystem-seo-smoke-'));
const token = randomBytes(32).toString('hex');
let outboundRequests = 0;
let runtime;

try {
  runtime = new Miniflare({
    modules: true,
    scriptPath: workerPath,
    compatibilityDate: '2025-06-17',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    defaultPersistRoot: stateDir,
    cachePersist: false,
    d1Databases: { DB: 'seo-agent-smoke-db' },
    d1Persist: join(stateDir, 'd1'),
    kvNamespaces: ['OVERRIDES'],
    kvPersist: join(stateDir, 'kv'),
    queueProducers: { DRAFT_QUEUE: 'seo-agent-smoke-drafts' },
    bindings: {
      AGENT_TOKEN: token,
      SITE_URL: 'https://dunesub.de',
      SITE_NAME: 'DuneSub',
      AUTO_APPLY_FIELDS: '',
      AEO_CHECKS: 'false',
      CITATION_QUERIES: '[]',
    },
    outboundService: () => {
      outboundRequests += 1;
      throw new Error('Outbound requests are disabled during the local SEO smoke check');
    },
  });

  const db = await runtime.getD1Database('DB');
  const kv = await runtime.getKVNamespace('OVERRIDES');
  const schema = await readFile(new URL('schema.sql', serviceUrl), 'utf8');
  // The shipped schema contains simple DDL statements and line comments.
  const statements = schema.replace(/--[^\n]*/g, '').split(';').map((sql) => sql.trim()).filter(Boolean);
  await db.batch(statements.map((sql) => db.prepare(sql)));

  async function request(path, { method = 'GET', body, auth = true, expectedStatus = 200 } = {}) {
    const headers = { 'content-type': 'application/json' };
    if (auth) headers.authorization = `Bearer ${token}`;
    const response = await runtime.dispatchFetch(`http://seo-agent.local${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const data = await response.json();
    assert.equal(response.status, expectedStatus, `${method} ${path}: ${JSON.stringify(data)}`);
    return data;
  }

  assert.deepEqual(await request('/status', { auth: false, expectedStatus: 401 }), { error: 'unauthorized' });
  const emptyStatus = await request('/status');
  assert.equal(emptyStatus.lastRun, null);
  assert.equal(emptyStatus.running, false);
  assert.equal(emptyStatus.config.aeoChecks, false);
  assert.deepEqual(await request('/findings'), []);
  assert.deepEqual(await request('/proposals'), []);

  const path = '/integration-smoke';
  const snapshotTitle = 'DuneSub original page';
  const liveTitle = 'DuneSub previously approved title';
  const proposedTitle = 'DuneSub community and discoveries';
  const preservedDescription = 'Existing description override stays intact.';
  const now = new Date().toISOString();
  await db.batch([
    db.prepare('INSERT INTO crawl_runs (id, started_at, finished_at, url_count, ok, pipeline_done) VALUES (1, ?, ?, 1, 1, 1)').bind(now, now),
    db.prepare('INSERT INTO page_snapshots (run_id, path, status, title, description, fetched_at) VALUES (1, ?, 200, ?, ?, ?)')
      .bind(path, snapshotTitle, 'Original page description.', now),
    db.prepare('INSERT INTO findings (created_at, run_id, path, rule, severity, detail) VALUES (?, 1, ?, ?, ?, ?)')
      .bind(now, path, 'title_too_long', 'medium', 'Seeded local runtime check'),
  ]);
  await kv.put(`override:${path}`, JSON.stringify({ title: liveTitle, description: preservedDescription }));

  const findings = await request('/findings');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].path, path);
  assert.equal(findings[0].status, 'open');
  const seededStatus = await request('/status');
  assert.equal(seededStatus.lastRun.id, 1);
  assert.deepEqual(seededStatus.openFindingsBySeverity, [{ severity: 'medium', n: 1 }]);

  const proposal = await request('/proposals', {
    method: 'POST',
    body: { path, field: 'title', value: proposedTitle, rationale: 'Local runtime verification' },
  });
  assert.ok(Number.isInteger(proposal.id) && proposal.id > 0);
  assert.equal(proposal.status, 'proposed');
  const pending = await request('/proposals');
  assert.equal(pending.length, 1);
  assert.equal(pending[0].current_value, snapshotTitle);
  assert.equal(pending[0].proposed_value, proposedTitle);

  const approval = await request(`/proposals/${proposal.id}/approve`, { method: 'POST' });
  assert.equal(approval.status, 'approved');
  assert.ok(Number.isInteger(approval.changeId) && approval.changeId > 0);
  assert.deepEqual(await kv.get(`override:${path}`, 'json'), { title: proposedTitle, description: preservedDescription });
  const overrides = await request('/overrides');
  assert.equal(overrides.length, 1);
  assert.equal(overrides[0].key, `override:${path}`);
  assert.deepEqual(JSON.parse(overrides[0].value), { title: proposedTitle, description: preservedDescription });
  const change = await db.prepare('SELECT old_value, new_value, proposal_id, reverted_at FROM changes WHERE id = ?').bind(approval.changeId).first();
  assert.deepEqual(change, { old_value: liveTitle, new_value: proposedTitle, proposal_id: proposal.id, reverted_at: null });
  assert.equal((await request('/changes'))[0].id, approval.changeId);
  assert.equal((await request('/proposals?status=approved'))[0].id, proposal.id);

  const rejected = await request('/proposals', {
    method: 'POST',
    body: { path, field: 'title', value: 'DuneSub alternative community title' },
  });
  const rejection = await request(`/proposals/${rejected.id}/reject`, { method: 'POST' });
  assert.equal(rejection.status, 'rejected');
  assert.equal((await request('/proposals?status=rejected'))[0].id, rejected.id);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM changes').first()).n, 1);
  assert.equal((await kv.get(`override:${path}`, 'json')).title, proposedTitle);

  assert.deepEqual(await request(`/changes/${approval.changeId}/revert`, { method: 'POST' }), { ok: true });
  assert.deepEqual(await kv.get(`override:${path}`, 'json'), { title: liveTitle, description: preservedDescription });
  const restoredOverrides = await request('/overrides');
  assert.deepEqual(JSON.parse(restoredOverrides[0].value), { title: liveTitle, description: preservedDescription });
  const reverted = await db.prepare('SELECT status FROM proposals WHERE id = ?').bind(proposal.id).first();
  assert.equal(reverted.status, 'reverted');
  assert.ok((await db.prepare('SELECT reverted_at FROM changes WHERE id = ?').bind(approval.changeId).first()).reverted_at);
  await request(`/changes/${approval.changeId}/revert`, { method: 'POST', expectedStatus: 409 });
  assert.equal(outboundRequests, 0, 'The smoke check must not make outbound requests');

  console.log('SEO Worker runtime smoke passed: authentication, D1 findings/proposals, approval, rejection, KV overrides, and rollback; zero outbound requests.');
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  throw new Error(message.replaceAll(token, '[redacted]'));
} finally {
  try {
    await runtime?.dispose();
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
}
