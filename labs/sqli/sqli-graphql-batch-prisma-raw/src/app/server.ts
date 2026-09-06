// SPDX-License-Identifier: MIT
// "Field Reports" API server.
//
// Wires an Apollo Server 4 GraphQL endpoint (the vulnerable surface) into an
// Express app that also serves a few plain-HTTP helper routes:
//   GET  /health   -> "ok"                      (liveness)
//   GET  /         -> short usage text
//   GET  /metrics  -> resolver-call counters    (batch-tuning aid)
//   POST /graphql  -> Apollo GraphQL (searchReports + metrics)
//   POST /solve    -> exchange the recovered secret for the per-container flag
import { readFileSync } from 'fs';
import express, { NextFunction, Request, Response } from 'express';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { prisma, metrics } from './db';
import { typeDefs } from './schema';
import { resolvers } from './resolvers';

const PORT = 8080;
const FLAG_PATH = process.env.FLAG_PATH || '/var/lib/lab/flag.txt';

function readFlag(): string {
  // Read the flag file directly in code (never shell out). The file lives on a
  // tmpfs and is written by entrypoint.sh before the server starts.
  try {
    return readFileSync(FLAG_PATH, 'utf8').trim();
  } catch {
    return '(flag unavailable)';
  }
}

async function main(): Promise<void> {
  const apollo = new ApolloServer({
    typeDefs,
    resolvers,
    // Introspection stays on: exploring the schema is part of the lesson, and it
    // is not what makes this lab vulnerable.
    introspection: true,
  });
  await apollo.start();

  const app = express();
  app.use(express.json({ limit: '2mb' }));

  app.get('/health', (_req: Request, res: Response) => {
    res.type('text/plain').send('ok');
  });

  app.get('/', (_req: Request, res: Response) => {
    res
      .type('text/plain')
      .send(
        [
          'Field Reports API.',
          '',
          'POST /graphql   { query: \'query { searchReports(filter: "a") { id title } }\' }',
          'GET  /metrics   resolver-call counters (tune your batch size)',
          'POST /solve     { "flag": "<40-char secret>" } -> returns the flag on match',
          '',
        ].join('\n'),
      );
  });

  app.get('/metrics', (_req: Request, res: Response) => {
    res.json({
      searchReportsCalls: metrics.searchReportsCalls,
      graphqlRequests: metrics.graphqlRequests,
    });
  });

  // POST /solve — exchange the recovered per-container secret for the flag. This
  // route is written the SAFE way: the DB lookup is a bound Prisma query, and the
  // flag is only released on an exact match. It is not an injection point.
  app.post('/solve', async (req: Request, res: Response) => {
    const submitted = req.body && typeof req.body.flag === 'string' ? req.body.flag : '';
    let real = '';
    try {
      const row = await prisma.secret.findFirst({ orderBy: { id: 'asc' } });
      real = row ? row.batchFlag : '';
    } catch {
      real = '';
    }
    if (submitted.length > 0 && submitted === real) {
      res.json({ flag: readFlag() });
      return;
    }
    res.status(200).json({ ok: false });
  });

  // GraphQL endpoint. The small middleware in front counts HTTP-level requests so
  // /metrics can show batching amplification (1 request, N resolver calls).
  app.use(
    '/graphql',
    (_req: Request, _res: Response, next: NextFunction) => {
      metrics.graphqlRequests += 1;
      next();
    },
    expressMiddleware(apollo),
  );

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] listening on 0.0.0.0:${PORT}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
