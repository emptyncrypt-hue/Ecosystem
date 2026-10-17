const MAX_RESPONSE_BYTES = 1024 * 1024;
const FINDING_STATUSES = new Set(['open', 'resolved', 'dismissed']);
const PROPOSAL_STATUSES = new Set(['proposed', 'approved', 'rejected', 'reverted']);

/** A sanitized failure. `status` is present for HTTP failures; `code` is stable. */
export class SeoAgentError extends Error {
  constructor(message, { code = 'response', status } = {}) {
    super(message);
    this.name = 'SeoAgentError';
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}

function invalidConfig(message) {
  throw new SeoAgentError(message, { code: 'config' });
}

function originFrom(value) {
  // Check the supplied spelling too: URL normalization can otherwise hide paths,
  // empty userinfo, query delimiters, backslashes, or surrounding whitespace.
  if (typeof value !== 'string' || /[\s\\]/u.test(value) || !/^https?:\/\/[^/?#]+\/?$/i.test(value)) {
    invalidConfig('SEO agent URL must be an HTTPS origin with no credentials, path, query, or fragment.');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    invalidConfig('SEO agent URL must be a valid HTTPS origin.');
  }
  const authority = value.slice(value.indexOf('://') + 3).replace(/\/$/u, '');
  if (authority.includes('@') || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    invalidConfig('SEO agent URL must have no credentials, path, query, or fragment.');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(authority))) {
    invalidConfig('SEO agent URL requires HTTPS; HTTP is allowed only on localhost, 127.0.0.1, or [::1].');
  }
  return url.origin;
}

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const positiveId = (value) => Number.isSafeInteger(value) && value > 0;
const rows = (value, validate) => Array.isArray(value) && value.every((row) => object(row) && validate(row));
const identifiedRow = (value) => positiveId(value.id) && typeof value.path === 'string';

const shapes = {
  status: (value) => object(value) && typeof value.running === 'boolean' &&
    (value.lastRun === null || object(value.lastRun)) && Array.isArray(value.openFindingsBySeverity) && Array.isArray(value.proposalsByStatus),
  findings: (value) => rows(value, (row) => identifiedRow(row) && typeof row.rule === 'string' &&
    typeof row.severity === 'string' && FINDING_STATUSES.has(row.status)),
  proposals: (value) => rows(value, (row) => identifiedRow(row) && typeof row.field === 'string' &&
    typeof row.proposed_value === 'string' && PROPOSAL_STATUSES.has(row.status)),
  changes: (value) => rows(value, (row) => identifiedRow(row) && typeof row.field === 'string'),
  overrides: (value) => rows(value, (row) => typeof row.key === 'string' && (row.value === null || typeof row.value === 'string')),
  analytics: (value) => object(value) && object(value.gsc) && typeof value.gsc.active === 'boolean' && Array.isArray(value.gsc.daily) &&
    object(value.aeo) && Array.isArray(value.aeo.daily) && Array.isArray(value.aeo.weekly) && Array.isArray(value.aeo.topBots7d) &&
    object(value.citations) && typeof value.citations.active === 'boolean' && Array.isArray(value.citations.series) &&
    object(value.findings) && Array.isArray(value.findings.series) && Array.isArray(value.changes),
  run: (value) => object(value) && value.started === true && value.running === true,
  approve: (value, id) => object(value) && value.ok === true && value.id === id && value.status === 'approved' && positiveId(value.changeId),
  reject: (value, id) => object(value) && value.ok === true && value.id === id && value.status === 'rejected',
  revert: (value) => object(value) && value.ok === true,
};

function discardBody(response) {
  // Cancellation is best effort and cannot delay reporting a failure.
  try {
    response.body?.cancel().catch(() => {});
  } catch { /* A locked or already closed body needs no further action. */ }
}

async function readJson(response, signal) {
  const length = response.headers?.get('content-length');
  if (length !== null && length !== undefined && /^\d+$/u.test(length) && Number(length) > MAX_RESPONSE_BYTES) {
    discardBody(response);
    throw new SeoAgentError('SEO agent response exceeds the 1 MiB limit.');
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw new SeoAgentError('SEO agent returned an invalid JSON response.');
  }
  const reader = response.body.getReader();
  const cancel = () => { reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  if (signal.aborted) cancel();
  const chunks = [];
  let bytes = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) {
        reader.cancel().catch(() => {});
        throw new SeoAgentError('SEO agent response exceeds the 1 MiB limit.');
      }
      chunks.push(value);
    }
    const buffer = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) {
      buffer.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
  } catch (error) {
    if (error instanceof SeoAgentError) throw error;
    throw new SeoAgentError('SEO agent returned an unreadable or invalid JSON response.');
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

/**
 * Connect to an existing seo-agent Worker. No request is retried automatically.
 * `run()` returns the upstream 202 result; an already active run throws code
 * `busy`, status 409. A timeout after a POST may leave its outcome uncertain.
 */
export function createSeoAgentClient({ url, token, timeoutMs = 15_000, fetchImpl = globalThis.fetch } = {}) {
  const origin = originFrom(url);
  if (typeof token !== 'string' || !token.trim() || /[\r\n]/u.test(token)) {
    invalidConfig('Set a nonempty SEO agent token without line breaks.');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) {
    invalidConfig('SEO agent timeout must be a positive integer of at most 2147483647 milliseconds.');
  }
  if (typeof fetchImpl !== 'function') invalidConfig('SEO agent requires a fetch implementation.');
  const authorization = `Bearer ${token.trim()}`;

  async function request(method, resource, shape, id) {
    const controller = new AbortController();
    let timedOut = false;
    let timer;
    const deadline = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
        reject(new SeoAgentError('SEO agent request timed out; inspect status before retrying a write.', { code: 'timeout' }));
      }, timeoutMs);
    });
    async function perform() {
      let response;
      try {
        response = await fetchImpl(`${origin}${resource}`, {
          method, headers: { Authorization: authorization, Accept: 'application/json' },
          redirect: 'error', signal: controller.signal,
        });
      } catch {
        throw new SeoAgentError('SEO agent request failed; check network access and the configured origin.', { code: 'network' });
      }
      if (!response.ok) {
        discardBody(response);
        const status = Number.isInteger(response.status) ? response.status : undefined;
        if (method === 'POST' && resource === '/run' && status === 409) {
          throw new SeoAgentError('An SEO agent run is already in progress; inspect status before retrying.', { code: 'busy', status });
        }
        throw new SeoAgentError(`SEO agent request failed${status === undefined ? '' : ` (HTTP ${status})`}.`, { code: 'http', status });
      }
      const value = await readJson(response, controller.signal);
      if (!shapes[shape](value, id)) throw new SeoAgentError('SEO agent returned an unexpected response shape.');
      return value;
    }
    try {
      return await Promise.race([perform(), deadline]);
    } catch (error) {
      if (timedOut) throw new SeoAgentError('SEO agent request timed out; inspect status before retrying a write.', { code: 'timeout' });
      if (error instanceof SeoAgentError) throw error;
      throw new SeoAgentError('SEO agent returned an invalid response.');
    } finally {
      clearTimeout(timer);
    }
  }

  function filtered(resource, status, allowed, shape) {
    if (!allowed.has(status)) throw new SeoAgentError(`Invalid SEO agent ${shape} status.`, { code: 'input' });
    return request('GET', `${resource}?status=${encodeURIComponent(status)}`, shape);
  }

  function action(resource, id, verb) {
    if (!positiveId(id)) throw new SeoAgentError('SEO agent ID must be a positive safe integer.', { code: 'input' });
    return request('POST', `${resource}/${id}/${verb}`, verb, id);
  }

  return Object.freeze({
    status: () => request('GET', '/status', 'status'),
    findings: (status = 'open') => filtered('/findings', status, FINDING_STATUSES, 'findings'),
    proposals: (status = 'proposed') => filtered('/proposals', status, PROPOSAL_STATUSES, 'proposals'),
    changes: () => request('GET', '/changes', 'changes'),
    overrides: () => request('GET', '/overrides', 'overrides'),
    analytics: () => request('GET', '/analytics/summary', 'analytics'),
    run: () => request('POST', '/run', 'run'),
    approve: (id) => action('/proposals', id, 'approve'),
    reject: (id) => action('/proposals', id, 'reject'),
    revert: (id) => action('/changes', id, 'revert'),
  });
}
