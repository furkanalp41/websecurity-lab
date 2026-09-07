// SPDX-License-Identifier: MIT
//
// Wait for Elasticsearch, then create `logs` and `.credentials` indices. The
// secret_key stored under `.credentials/flag` is derived from LAB_USER_SECRET
// (unique per container) — the raw secret NEVER leaves the app container.
import { Client } from '@elastic/elasticsearch';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';

const ES_URL = process.env.ES_URL ?? 'http://es:9200';
const es = new Client({ node: ES_URL, requestTimeout: 20000 });

async function waitReady() {
  for (let i = 0; i < 90; i++) {
    try {
      const r = await es.cluster.health({ timeout: '2s' });
      if (r.status === 'green' || r.status === 'yellow') return;
    } catch {
      /* transient */
    }
    if (i === 0) console.log('[seed] waiting for elasticsearch...');
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('[seed] elasticsearch never became ready');
}

async function main() {
  await waitReady();

  // logs index — benign public search surface
  await es.indices
    .create({ index: 'logs', settings: { number_of_shards: 1, number_of_replicas: 0 } })
    .catch((e) => {
      if (e?.meta?.body?.error?.type !== 'resource_already_exists_exception') throw e;
    });

  // .credentials — hidden index; the app scopes /search to `logs` but the DSL
  // sink lets a caller widen the scope to reach this via body-side filters.
  await es.indices
    .create({ index: '.credentials', settings: { number_of_shards: 1, number_of_replicas: 0 } })
    .catch((e) => {
      if (e?.meta?.body?.error?.type !== 'resource_already_exists_exception') throw e;
    });

  const secret = process.env.LAB_USER_SECRET;
  if (!secret) throw new Error('[seed] LAB_USER_SECRET not set');
  // 32 hex chars of deterministic-per-container pseudo-randomness.
  const secretKey = createHmac('sha256', secret)
    .update('credentials|sqli-elasticsearch-dsl-painless')
    .digest('hex')
    .slice(0, 32);
  await es.index({
    index: '.credentials',
    id: 'flag',
    refresh: 'true',
    document: { secret_key: secretKey, note: 'internal cluster access token — do not expose' },
  });

  const seeds = [
    { message: 'GET /health -> 200', client: '10.0.0.9', ts: '2026-09-01T09:00:00Z' },
    { message: 'POST /login -> 401', client: '10.0.0.14', ts: '2026-09-01T09:01:12Z' },
    { message: 'GET /metrics -> 200', client: '10.0.0.9', ts: '2026-09-01T09:01:45Z' },
    { message: 'POST /login -> 200', client: '10.0.0.22', ts: '2026-09-01T09:02:30Z' },
    { message: 'GET /profile -> 200', client: '10.0.0.22', ts: '2026-09-01T09:03:11Z' },
  ];
  for (const [i, doc] of seeds.entries()) {
    await es.index({ index: 'logs', id: String(i + 1), refresh: 'true', document: doc });
  }
  console.log('[seed] elasticsearch store ready');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
