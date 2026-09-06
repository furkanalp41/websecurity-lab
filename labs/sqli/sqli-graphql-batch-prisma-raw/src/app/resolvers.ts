// SPDX-License-Identifier: MIT
// GraphQL resolvers.
//
// The searchReports resolver is the deliberately vulnerable sink: the caller's
// `filter` string is concatenated straight into a SQL statement and handed to
// prisma.$queryRawUnsafe (CWE-89). Prisma's $queryRaw / template-tagged form
// would parameterise safely; $queryRawUnsafe does NOT — it runs whatever text it
// is given. Because GraphQL lets one request carry many aliased operations, an
// attacker can fire hundreds of boolean-blind probes per HTTP round-trip.
import { prisma, metrics } from './db';

interface ReportRow {
  id: number | bigint;
  title: string;
}

export const resolvers = {
  Query: {
    searchReports: async (
      _parent: unknown,
      args: { filter: string },
    ): Promise<Array<{ id: number; title: string }>> => {
      metrics.searchReportsCalls += 1;

      // VULNERABILITY (CWE-89): `filter` is spliced into the query text with no
      // parameterization, escaping, or allowlist. Anything the caller sends
      // becomes SQL. The "safe-looking" LIKE search is a full injection point.
      const sql = "SELECT id, title FROM reports WHERE title LIKE '%" + args.filter + "%'";

      let rows: ReportRow[] = [];
      try {
        // $queryRawUnsafe runs the raw string as-is. (The safe sibling is the
        // tagged-template prisma.$queryRaw`...` which binds parameters.)
        rows = (await prisma.$queryRawUnsafe(sql)) as ReportRow[];
      } catch {
        // Stay "blind": a syntactically broken injection simply yields no rows
        // rather than an error the attacker could read. The boolean channel is
        // "did this return >= 1 row", nothing more.
        rows = [];
      }

      return rows.map((r) => ({ id: Number(r.id), title: r.title }));
    },

    metrics: () => ({
      searchReportsCalls: metrics.searchReportsCalls,
      graphqlRequests: metrics.graphqlRequests,
    }),
  },
};
