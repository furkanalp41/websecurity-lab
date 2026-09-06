// SPDX-License-Identifier: MIT
import { PrismaClient } from '@prisma/client';

// Postgres returns 64-bit integer types (e.g. count(*) -> int8) as JavaScript
// BigInt, which JSON.stringify cannot serialise. Teach BigInt how to serialise
// so any stray value in a raw-query result never crashes the JSON response.
(BigInt.prototype as unknown as { toJSON: () => number }).toJSON = function (this: bigint): number {
  return Number(this);
};

export const prisma = new PrismaClient();
