import { afterEach, describe, it, expect, vi } from 'vitest';
import { parseSitemap, dedupeAndCap, runCrawl } from '../src/crawl';

const ORIGIN = 'https://example.com';

describe('parseSitemap', () => {
  it('parses a <urlset> into entries (same-origin only)', () => {
    const xml = `<?xml version="1.0"?><urlset>
      <url><loc>https://example.com/a</loc><lastmod>2026-01-01</lastmod></url>
      <url><loc>https://example.com/b</loc></url>
      <url><loc>https://other.com/c</loc></url>
    </urlset>`;
    const { entries, sitemaps } = parseSitemap(xml, ORIGIN);
    expect(entries).toEqual([
      { loc: 'https://example.com/a', lastmod: '2026-01-01' },
      { loc: 'https://example.com/b', lastmod: null },
    ]);
    expect(sitemaps).toEqual([]);
  });

  it('parses a <sitemapindex> into child sitemap locations', () => {
    const xml = `<?xml version="1.0"?><sitemapindex>
      <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
      <sitemap><loc>https://example.com/sitemap-2.xml</loc></sitemap>
      <sitemap><loc>https://cdn.other.com/s.xml</loc></sitemap>
    </sitemapindex>`;
    const { entries, sitemaps } = parseSitemap(xml, ORIGIN);
    expect(entries).toEqual([]);
    expect(sitemaps).toEqual(['https://example.com/sitemap-1.xml', 'https://example.com/sitemap-2.xml']);
  });

  it('compares exact origins and rejects credentials, malformed URLs, and lookalike hosts', () => {
    const rejected = [
      'https://example.com.evil.test/a',
      'https://example.com:8443/a',
      'http://example.com/a',
      'https://example.com@evil.test/a',
      'https://user:password@example.com/a',
      'https://user@example.com/a',
      'https:////example.com/a',
      'https://example.com\\evil.test/a',
      'https://example.com/a b',
      '//example.com/a',
      'not-a-url',
    ];
    const xml = `<urlset>${rejected.map((loc) => `<url><loc>${loc}</loc></url>`).join('')}
      <url><loc>https://EXAMPLE.com:443/valid</loc></url></urlset>`;
    expect(parseSitemap(xml, ORIGIN).entries).toEqual([{ loc: `${ORIGIN}/valid`, lastmod: null }]);
  });

  it('ignores external sitemap locations unless their HTTPS origin is explicitly allowed', () => {
    const xml = `<urlset><url><loc>https://legacy.example/home</loc></url></urlset>`;
    expect(parseSitemap(xml, ORIGIN).entries).toEqual([]);
    expect(parseSitemap(xml, ORIGIN, ['https://legacy.example']).entries).toEqual([
      { loc: `${ORIGIN}/home`, lastmod: null },
    ]);
  });

  it('remaps allowed alias entries and child sitemaps while preserving paths and queries', () => {
    const xml = `<urlset>
      <url><loc>https://legacy.example/articles/a%20b?first=1&amp;second=two%20words</loc><lastmod>2026-10-18</lastmod></url>
      <url><loc>https://legacy.example.evil.test/ignore</loc></url>
      <url><loc>https://user@legacy.example/ignore</loc></url>
      <url><loc>http://legacy.example/ignore</loc></url>
    </urlset><sitemapindex>
      <sitemap><loc>https://legacy.example/maps/pages.xml?part=2&amp;lang=en</loc></sitemap>
      <sitemap><loc>https://elsewhere.example/ignore.xml</loc></sitemap>
    </sitemapindex>`;
    expect(parseSitemap(xml, ORIGIN, ['https://legacy.example'])).toEqual({
      entries: [{ loc: `${ORIGIN}/articles/a%20b?first=1&second=two%20words`, lastmod: '2026-10-18' }],
      sitemaps: [`${ORIGIN}/maps/pages.xml?part=2&lang=en`],
    });
  });

  it.each([
    'http://legacy.example',
    'https://legacy.example/path',
    'https://legacy.example?query=1',
    'https://legacy.example#fragment',
    'https://user:password@legacy.example',
    'https:////legacy.example',
    'not-a-url',
  ])('ignores an invalid alias origin: %s', (alias) => {
    const xml = `<urlset><url><loc>https://legacy.example/home</loc></url></urlset>`;
    expect(parseSitemap(xml, ORIGIN, [alias]).entries).toEqual([]);
  });

  it('keeps paths beginning with two slashes on the canonical host', () => {
    const xml = `<urlset><url><loc>https://legacy.example//other.example/home?x=1</loc></url></urlset>`;
    expect(parseSitemap(xml, ORIGIN, ['https://legacy.example']).entries).toEqual([
      { loc: `${ORIGIN}//other.example/home?x=1`, lastmod: null },
    ]);
  });
});

describe('runCrawl sitemap aliases', () => {
  afterEach(() => vi.unstubAllGlobals());

  function environment(aliases?: string): Env {
    const statement = { bind: vi.fn().mockReturnThis(), run: vi.fn().mockResolvedValue({ success: true }) };
    return {
      SITE_URL: ORIGIN,
      SITEMAP_ORIGIN_ALIASES: aliases,
      DB: { prepare: vi.fn(() => statement), batch: vi.fn().mockResolvedValue([]) },
    } as unknown as Env;
  }

  it('fetches aliased child sitemaps and pages only at the canonical origin', async () => {
    const responses: Record<string, string> = {
      [`${ORIGIN}/sitemap.xml`]: `<sitemapindex>
        <sitemap><loc>https://legacy.example/maps/pages.xml?part=1&amp;lang=en</loc></sitemap>
        <sitemap><loc>https://untrusted.example/ignore.xml</loc></sitemap>
      </sitemapindex>`,
      [`${ORIGIN}/maps/pages.xml?part=1&lang=en`]: `<urlset>
        <url><loc>https://legacy.example/home?view=public&amp;lang=en</loc></url>
        <url><loc>https://second.example/about</loc></url>
        <url><loc>https://untrusted.example/ignore</loc></url>
      </urlset>`,
      [`${ORIGIN}/home?view=public&lang=en`]: 'home',
      [`${ORIGIN}/about`]: 'about',
    };
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      expect(new URL(input).origin).toBe(ORIGIN);
      expect(init?.redirect).toBe('manual');
      if (!(input in responses)) throw new Error(`Unexpected request: ${input}`);
      return new Response(responses[input], { headers: { 'content-type': 'text/plain' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    const result = await runCrawl(environment(' https://legacy.example , https://second.example, '), 42);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual(Object.keys(responses));
    expect(result.snapshots.map((snapshot) => snapshot.path).sort()).toEqual(['/about', '/home']);
    expect(result.snapshots.every((snapshot) => snapshot.status === 200 && snapshot.error === null)).toBe(true);
  });

  it('rejects a redirecting root sitemap without following its external destination', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, {
      status: 302,
      headers: { location: 'https://legacy.example/sitemap.xml' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(runCrawl(environment('https://legacy.example'), 43)).rejects.toThrow('sitemap fetch failed: 302');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(`${ORIGIN}/sitemap.xml`, expect.objectContaining({ redirect: 'manual' }));
  });

  it('does not crawl alias pages when no aliases are configured', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      '<urlset><url><loc>https://legacy.example/home</loc></url></urlset>'
    ));
    vi.stubGlobal('fetch', fetchMock);
    await expect(runCrawl(environment(), 44)).rejects.toThrow('sitemap parsed to zero URLs');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not follow a child sitemap redirect to an alias host', async () => {
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      expect(init?.redirect).toBe('manual');
      if (input === `${ORIGIN}/sitemap.xml`) {
        return new Response('<sitemapindex><sitemap><loc>https://legacy.example/child.xml</loc></sitemap></sitemapindex>');
      }
      if (input === `${ORIGIN}/child.xml`) {
        return new Response(null, { status: 302, headers: { location: 'https://legacy.example/child.xml' } });
      }
      throw new Error(`Unexpected request: ${input}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    await expect(runCrawl(environment('https://legacy.example'), 45)).rejects.toThrow('sitemap parsed to zero URLs');
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([`${ORIGIN}/sitemap.xml`, `${ORIGIN}/child.xml`]);
  });
});

describe('dedupeAndCap', () => {
  it('dedupes by loc, keeping first occurrence', () => {
    const { entries, truncated } = dedupeAndCap(
      [
        { loc: 'https://example.com/a', lastmod: '1' },
        { loc: 'https://example.com/a', lastmod: '2' },
        { loc: 'https://example.com/b', lastmod: null },
      ],
      2000
    );
    expect(entries.map((e) => e.loc)).toEqual(['https://example.com/a', 'https://example.com/b']);
    expect(entries[0].lastmod).toBe('1');
    expect(truncated).toBe(false);
  });

  it('caps the total and flags truncation', () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ loc: `https://example.com/${i}`, lastmod: null }));
    const { entries, truncated } = dedupeAndCap(many, 3);
    expect(entries).toHaveLength(3);
    expect(truncated).toBe(true);
  });
});
