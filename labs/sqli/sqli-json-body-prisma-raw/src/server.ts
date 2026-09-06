// SPDX-License-Identifier: MIT
//
// Report service — deliberately vulnerable JSON API (CWE-89).
//
// POST /api/reports accepts {"filter":{"status":"open"}}. The developer reached
// for prisma.$queryRawUnsafe to "filter by status", forgetting that unlike the
// tagged-template prisma.$queryRaw (which parameterises), $queryRawUnsafe takes a
// plain string and runs it verbatim. The JSON status VALUE is concatenated
// straight into the SQL text, so a crafted status breaks out of the string
// literal and appends a UNION SELECT. Verbose DB errors are returned to help the
// learner line up the UNION column count and types.

import { readFileSync } from 'node:fs';
import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import { prisma } from './db';

const FLAG_PATH = process.env.FLAG_PATH ?? '/var/lib/lab/flag.txt';
const PORT = Number(process.env.PORT ?? 8080);

const app = Fastify({ logger: false, bodyLimit: 64 * 1024 });

app.get('/health', async (_req: FastifyRequest, reply: FastifyReply) => {
  reply.type('text/plain').send('ok');
});

app.get('/', async (_req: FastifyRequest, reply: FastifyReply) => {
  reply
    .type('text/plain')
    .send(
      'Report service.\n' +
        'POST /api/reports  {"filter":{"status":"open"}}\n' +
        'POST /solve        {"id":<audit-log id>}\n',
    );
});

interface ReportFilterBody {
  filter?: { status?: unknown };
}

app.post('/api/reports', async (req: FastifyRequest, reply: FastifyReply) => {
  const body = (req.body ?? {}) as ReportFilterBody;
  const status = body.filter?.status;

  if (typeof status !== 'string') {
    reply
      .code(400)
      .type('application/json')
      .send({ error: 'body must be {"filter":{"status":"<string>"}}' });
    return;
  }

  // VULNERABILITY (CWE-89): the JSON `status` value is concatenated straight
  // into the SQL text and executed with $queryRawUnsafe. $queryRawUnsafe does
  // NOT parameterise — it is plain string concatenation — so this is a textbook
  // SQL injection despite the "safe by default" reputation of Prisma.
  const sql = "SELECT id, title, status FROM reports WHERE status = '" + status + "'";

  try {
    const rows = await prisma.$queryRawUnsafe(sql);
    reply.type('application/json').send({ query: sql, rows });
  } catch (err) {
    // Verbose DB errors are intentionally echoed (the teaching channel): they
    // reveal UNION arity/type mismatches while the learner tunes the payload.
    const message = err instanceof Error ? err.message : String(err);
    reply.code(500).type('application/json').send({ error: message, query: sql });
  }
});

interface SolveBody {
  id?: unknown;
}

app.post('/solve', async (req: FastifyRequest, reply: FastifyReply) => {
  const body = (req.body ?? {}) as SolveBody;
  const submitted = Number(body.id);

  if (!Number.isInteger(submitted)) {
    reply.code(400).type('application/json').send({ error: 'body must be {"id":<integer>}' });
    return;
  }

  // Safe, parameterised lookup of the per-container secret (the id of the
  // FLAG_ISSUE audit-log row) using the tagged-template API — the exact
  // counterpart to the unsafe call above. Nothing user-controlled is
  // concatenated here.
  const rows = (await prisma.$queryRaw`
    SELECT id FROM audit_logs WHERE action = ${'FLAG_ISSUE'} LIMIT 1
  `) as Array<{ id: number | bigint }>;

  const seededId = rows.length > 0 ? Number(rows[0].id) : undefined;

  if (seededId !== undefined && submitted === seededId) {
    let flag: string;
    try {
      // Established safer pattern: read the flag file directly in code. Never
      // shell out to read it.
      flag = readFileSync(FLAG_PATH, 'utf8').trim();
    } catch {
      flag = '(flag unavailable)';
    }
    reply.type('application/json').send({ flag });
    return;
  }

  reply.code(403).type('application/json').send({ error: 'Wrong audit-log id.' });
});

app
  .listen({ host: '0.0.0.0', port: PORT })
  .then((addr) => {
    // eslint-disable-next-line no-console
    console.log(`[server] listening on ${addr}`);
  })
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    process.exit(1);
  });
