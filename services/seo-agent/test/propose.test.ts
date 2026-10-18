import { describe, it, expect, vi } from 'vitest';
import { draftWithTrace, invalidReason } from '../src/propose';
import { createProposal } from '../src/actions';

describe('invalidReason (description validation)', () => {
  const ok = 'This is a plainly written meta description that lands comfortably within the seventy to one-sixty character band.';

  it('accepts a well-formed description', () => {
    expect(invalidReason(ok)).toBeNull();
  });
  it('rejects too-short copy (< 70 chars)', () => {
    expect(invalidReason('Too short.')).toMatch(/too short/);
  });
  it('rejects too-long copy (> 160 chars)', () => {
    expect(invalidReason('a'.repeat(170) + '.')).toMatch(/too long/);
  });
  it('rejects copy that does not end in sentence punctuation', () => {
    expect(invalidReason('a'.repeat(100))).toMatch(/complete sentence/);
  });
});

it('uses the configured platform context for drafts while keeping approval policy unchanged', async () => {
  const description = 'DuneSub Ecosystem combines policy tools, Cloudflare SEO automation, and verified integrations with approvals for metadata changes.';
  const ai = { run: vi.fn().mockResolvedValue({ response: description }) };
  const env = { SITE_URL: 'https://www.dunesub.de', SITE_NAME: 'DuneSub', SITE_DESCRIPTION: description, AI: ai, AUTO_APPLY_FIELDS: '' } as unknown as Env;
  const result = await draftWithTrace(env, { path: '/', title: 'DuneSub Ecosystem', current: null });
  expect(result.value).toBe(description);
  expect(ai.run.mock.calls[0][1].messages[0].content).toContain(description);
  expect(env.AUTO_APPLY_FIELDS).toBe('');
});

it('creates new manual proposals on the verified canonical homepage without changing historical proposals', async () => {
  const calls: Array<{ sql: string; bindings: unknown[] }> = [];
  const env = {
    SITE_URL: 'https://www.dunesub.de', HOMEPAGE_PATH_ALIASES: '/home',
    DB: { prepare(sql: string) {
      const entry = { sql, bindings: [] as unknown[] };
      calls.push(entry);
      return { bind(...values: unknown[]) { entry.bindings = values; return this; }, first: async () => sql.startsWith('SELECT') ? null : { id: 9 } };
    } },
  } as unknown as Env;
  const result = await createProposal(env, { path: '/home', field: 'title', value: 'DuneSub Ecosystem | Policy Tools & SEO Automation' }, invalidReason);
  expect(result).toEqual({ ok: true, id: 9, status: 'proposed' });
  expect(calls[0].bindings).toEqual(['/']);
  expect(calls[1].bindings[1]).toBe('/');
  expect(calls.every(({ sql }) => !/UPDATE|DELETE/.test(sql))).toBe(true);
  calls.length = 0;
  await createProposal(env, { path: '/homepage', field: 'title', value: 'Unrelated page' }, invalidReason);
  expect(calls[1].bindings[1]).toBe('/homepage');
});
