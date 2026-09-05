// SPDX-License-Identifier: MIT
import Database from 'better-sqlite3';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROGRESS_DB_PATH } from '../util/paths.js';

const here = dirname(fileURLToPath(import.meta.url));

/** Open (creating if needed) the progress DB and apply the schema idempotently. */
export function openDb(path: string = PROGRESS_DB_PATH): Database.Database {
  mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.exec(readFileSync(join(here, 'schema.sql'), 'utf8'));
  return db;
}
