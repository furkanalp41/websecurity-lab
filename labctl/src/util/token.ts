// SPDX-License-Identifier: MIT
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { LABCTL_DIR, TOKEN_PATH } from './paths.js';

/** Per-install bearer token for the local daemon; created at ~/.labctl/token (0600). */
export function loadOrCreateToken(): string {
  if (existsSync(TOKEN_PATH)) return readFileSync(TOKEN_PATH, 'utf8').trim();
  mkdirSync(LABCTL_DIR, { recursive: true, mode: 0o700 });
  const token = randomBytes(32).toString('hex');
  writeFileSync(TOKEN_PATH, `${token}\n`, { mode: 0o600 });
  return token;
}
