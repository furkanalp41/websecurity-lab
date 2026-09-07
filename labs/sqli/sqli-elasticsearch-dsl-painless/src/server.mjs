// SPDX-License-Identifier: MIT
//
// Acme LogSearch — a log-search UI whose /search endpoint forwards a
// user-supplied JSON body verbatim into Elasticsearch's _search DSL.
//
// The vulnerability (CWE-943 / CWE-89 sibling in the NoSQL family): the app
// scopes the search to `index: "logs"` (server-side) but the body is otherwise
// UNVALIDATED. A caller can inject any Query DSL clause — including one that
// widens the effective scope to another index (multi-index syntax in the search
// URL is refused, but the body's `terms:{_index:[...]}` filter is honored). The
// hidden `.credentials` index (an ordinary index that only the admin service
// should hit) exposes its `secret_key` field this way.
//
// Painless script_fields is offered as a companion vector: the app appends any
// caller-supplied `script_fields` block to the search body, so a Painless
// snippet can pull fields the app never selected (`_source`, `_index`, `_id`).
// In 8.x the sandbox blocks direct cross-index reads from Painless, so the
// script vector alone can't reach `.credentials` — it must be combined with the
// scope widening. See SOLUTION for the deviation from the catalog's original
// script-only framing.
import Fastify from 'fastify';
import { readFileSync } from 'node:fs';
import { Client } from '@elastic/elasticsearch';
import { timingSafeEqual } from 'node:crypto';

const FLAG_PATH = process.env.FLAG_PATH ?? '/var/lib/lab/flag.txt';
const ES_URL = process.env.ES_URL ?? 'http://es:9200';

const app = Fastify({ logger: false });
const es = new Client({ node: ES_URL, requestTimeout: 20000 });

app.get('/health', async () => 'ok');

app.get('/', async () => ({
  service: 'Acme LogSearch',
  endpoints: [
    'GET  /logs                     list recent log documents',
    "POST /search  {body}           run a search against the 'logs' index (body is forwarded verbatim into ES DSL)",
    'POST /solve   {secret_key}     submit the recovered .credentials secret_key',
  ],
}));

app.get('/logs', async (_req, reply) => {
  const r = await es.search({ index: 'logs', size: 5, query: { match_all: {} } });
  return { hits: r.hits.hits.map((h) => ({ _id: h._id, _source: h._source })) };
});

// The vulnerable endpoint. `body` is treated as an ES search body — anything
// the caller sends (query, script_fields, size, aggs, ...) reaches ES. The app
// explicitly SCOPES the URL-side index to "logs" and thinks that is enough.
app.post('/search', async (req, reply) => {
  const body = req.body ?? {};
  if (typeof body !== 'object' || Array.isArray(body)) {
    return reply.code(400).send({ ok: false, error: 'body must be an object' });
  }
  try {
    const r = await es.search({ index: 'logs', ...body });
    // Return the full ES response — including any script_fields the caller
    // asked for and every _source that matched. No response filtering.
    return { ok: true, took: r.took, hits: r.hits };
  } catch (e) {
    // Surface the ES error so learners can iterate on their DSL.
    return reply.code(200).send({ ok: false, error: String(e?.message ?? e) });
  }
});

app.post('/solve', async (req, reply) => {
  const { secret_key } = req.body ?? {};
  if (typeof secret_key !== 'string' || secret_key.length === 0) {
    return reply.code(400).send({ ok: false, error: 'secret_key required' });
  }
  let expected;
  try {
    const r = await es.get({ index: '.credentials', id: 'flag' });
    expected = r._source?.secret_key;
  } catch (e) {
    return reply.code(500).send({ ok: false, error: 'credentials store unavailable' });
  }
  if (typeof expected !== 'string' || expected.length === 0) {
    return reply.code(500).send({ ok: false, error: 'no secret on record' });
  }
  // Constant-time comparison (align with copy-program/moveit/fortinet).
  const a = Buffer.from(secret_key, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  const ok = a.length === b.length && timingSafeEqual(a, b);
  if (!ok) return reply.code(403).send({ ok: false, error: 'incorrect secret_key' });
  let flag;
  try {
    flag = readFileSync(FLAG_PATH, 'utf8').trim();
  } catch {
    return reply.code(500).send({ ok: false, error: 'flag unavailable' });
  }
  return { ok: true, flag };
});

app.listen({ host: '0.0.0.0', port: 8080 }).catch((e) => {
  console.error('[app] listen failed', e);
  process.exit(1);
});
