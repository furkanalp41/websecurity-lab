// SPDX-License-Identifier: MIT
//
// Idempotent seed: wait for Postgres, create the two tables, populate `reports`
// with a few rows, and populate `audit_logs` with decoys plus ONE FLAG_ISSUE row
// at a random, non-guessable id. The random id is the per-container secret: it is
// discovered dynamically by UNION-selecting from audit_logs, never guessed.

import { randomInt } from 'node:crypto';
import { prisma } from './db';

async function waitForDb(): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      await prisma.$queryRawUnsafe('SELECT 1');
      return;
    } catch {
      if (attempt === 0) {
        // eslint-disable-next-line no-console
        console.log('[seed] waiting for database...');
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  throw new Error('[seed] database never became ready');
}

async function main(): Promise<void> {
  await waitForDb();

  await prisma.$executeRawUnsafe(
    'CREATE TABLE IF NOT EXISTS reports ' +
      '(id serial PRIMARY KEY, title text NOT NULL, status text NOT NULL)',
  );
  await prisma.$executeRawUnsafe(
    'CREATE TABLE IF NOT EXISTS audit_logs ' +
      '(id serial PRIMARY KEY, action text NOT NULL, detail text NOT NULL)',
  );

  const reportCount = (await prisma.$queryRawUnsafe(
    'SELECT count(*)::int AS c FROM reports',
  )) as Array<{ c: number }>;
  if (reportCount[0].c === 0) {
    await prisma.$executeRawUnsafe(
      'INSERT INTO reports (title, status) VALUES ' +
        "('Quarterly access review', 'open'), " +
        "('Third-party vendor risk assessment', 'open'), " +
        "('Incident postmortem: cache stampede', 'closed'), " +
        "('Data retention policy audit', 'pending'), " +
        "('Privileged account recertification', 'open')",
    );
    // eslint-disable-next-line no-console
    console.log('[seed] reports ready');
  }

  const flagCount = (await prisma.$queryRawUnsafe(
    "SELECT count(*)::int AS c FROM audit_logs WHERE action = 'FLAG_ISSUE'",
  )) as Array<{ c: number }>;

  if (flagCount[0].c === 0) {
    const decoys: Array<[string, string]> = [
      ['LOGIN', 'user=analyst source=10.0.0.5'],
      ['EXPORT', 'table=reports rows=42'],
      ['CONFIG_CHANGE', 'setting=retention days=90'],
      ['LOGOUT', 'user=analyst'],
      ['LOGIN', 'user=admin source=10.0.0.9'],
      ['PURGE', 'table=sessions rows=1200'],
      ['EXPORT', 'table=audit_logs rows=7'],
    ];
    for (const [action, detail] of decoys) {
      await prisma.$executeRaw`INSERT INTO audit_logs (action, detail) VALUES (${action}, ${detail})`;
    }

    // The FLAG_ISSUE row sits at a random id well outside the decoys' serial
    // range so it cannot be guessed — it must be recovered via the injection.
    const randomId = randomInt(100000, 1000000);
    await prisma.$executeRaw`INSERT INTO audit_logs (id, action, detail) VALUES (${randomId}, ${'FLAG_ISSUE'}, ${'audit token issued; submit this row id to /solve'})`;
    // eslint-disable-next-line no-console
    console.log('[seed] audit_logs ready');
  } else {
    // eslint-disable-next-line no-console
    console.log('[seed] audit_logs already seeded');
  }

  await prisma.$disconnect();
}

main().catch(async (err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  try {
    await prisma.$disconnect();
  } catch {
    /* ignore */
  }
  process.exit(1);
});
