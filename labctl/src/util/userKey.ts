// SPDX-License-Identifier: MIT
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { USER_KEY_PATH, WEBSEC_DIR } from './paths.js';

/** Per-machine 32-byte secret; flags are derived from it and never leave the host. */
export function loadOrCreateUserKey(): string {
  if (existsSync(USER_KEY_PATH)) return readFileSync(USER_KEY_PATH, 'utf8').trim();
  mkdirSync(WEBSEC_DIR, { recursive: true, mode: 0o700 });
  const key = randomBytes(32).toString('hex');
  writeFileSync(USER_KEY_PATH, `${key}\n`, { mode: 0o600 });
  return key;
}
