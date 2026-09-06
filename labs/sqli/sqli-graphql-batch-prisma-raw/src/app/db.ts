// SPDX-License-Identifier: MIT
// Shared Prisma client. A single instance is reused across the whole process so
// batched GraphQL requests all draw from the same connection pool.
import { PrismaClient } from '@prisma/client';

export const prisma = new PrismaClient();

// Resolver-call telemetry. `/metrics` (and the GraphQL `metrics` query) expose
// these so a learner can see the amplification: one HTTP request that carries N
// aliased searchReports operations bumps searchReportsCalls by N while
// graphqlRequests only grows by 1. That ratio is the whole point of batching.
export const metrics = {
  searchReportsCalls: 0,
  graphqlRequests: 0,
};
