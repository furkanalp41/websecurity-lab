// SPDX-License-Identifier: MIT
// Idempotent database seeding, run once by entrypoint.sh AFTER the flag has been
// written and LAB_USER_SECRET unset.
//
// Creates the schema with raw SQL (so the runtime image needs no Prisma CLI or
// migration files), inserts a handful of public reports, and generates the
// per-container secret: secrets.batch_flag, a fresh 40-hex string on every boot.
// The secret is NOT the flag and never leaves the DB in one piece — it must be
// reconstructed one character at a time through the boolean-blind oracle.
import { randomBytes } from 'crypto';
import { prisma } from './db';

const REPORT_TITLES = [
  'Quarterly Threat Landscape',
  'Incident Response Retrospective',
  'Phishing Campaign Analysis',
  'Cloud Posture Review',
  'Red Team Engagement Summary',
];

async function waitForDb(): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      await prisma.$queryRawUnsafe('SELECT 1');
      return;
    } catch {
      if (attempt === 0) {
        console.log('[seed] waiting for database...');
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw new Error('[seed] database never became ready');
}

async function seed(): Promise<void> {
  await waitForDb();

  // DDL — matches prisma/schema.prisma. IF NOT EXISTS keeps this idempotent.
  await prisma.$executeRawUnsafe(
    'CREATE TABLE IF NOT EXISTS reports (id SERIAL PRIMARY KEY, title TEXT NOT NULL)',
  );
  await prisma.$executeRawUnsafe(
    'CREATE TABLE IF NOT EXISTS secrets (id SERIAL PRIMARY KEY, batch_flag TEXT NOT NULL)',
  );

  const reportCount = await prisma.report.count();
  if (reportCount === 0) {
    await prisma.report.createMany({
      data: REPORT_TITLES.map((title) => ({ title })),
    });
    console.log(`[seed] inserted ${REPORT_TITLES.length} reports`);
  }

  const secretCount = await prisma.secret.count();
  if (secretCount === 0) {
    // 20 random bytes -> 40 lowercase-hex characters. Regenerated per container
    // because the data directory lives on a tmpfs (see docker-compose.yml).
    const batchFlag = randomBytes(20).toString('hex');
    await prisma.secret.create({ data: { batchFlag } });
    console.log('[seed] secret provisioned (40-char batch_flag)');
  }

  console.log('[seed] ready');
}

seed()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
