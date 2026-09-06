// SPDX-License-Identifier: MIT
// GraphQL type definitions for the "Field Reports" API.
export const typeDefs = /* GraphQL */ `
  "A published field report. Only non-sensitive columns are exposed."
  type Report {
    id: Int!
    title: String!
  }

  "Resolver-call telemetry, surfaced to help tune batch sizes."
  type Metrics {
    "How many times the searchReports resolver has run since boot."
    searchReportsCalls: Int!
    "How many HTTP requests have hit the GraphQL endpoint since boot."
    graphqlRequests: Int!
  }

  type Query {
    """
    Full-text-ish search over report titles. The filter is substring-matched
    against the title. One HTTP request may carry many aliased searchReports
    operations, so a single round-trip can run hundreds of searches.
    """
    searchReports(filter: String!): [Report!]!

    "Live resolver-call counters (batch-tuning aid)."
    metrics: Metrics!
  }
`;
