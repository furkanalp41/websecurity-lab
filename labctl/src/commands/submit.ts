// SPDX-License-Identifier: MIT
import { verifyFlag } from '../util/flag.js';
import { loadOrCreateUserKey } from '../util/userKey.js';

/** Verify a flag guess against the local per-machine key (no network, no server). */
export function submit(slug: string, flag: string): void {
  const ok = verifyFlag(loadOrCreateUserKey(), slug, flag);
  if (ok) {
    console.log(`correct — ${slug} solved`);
    process.exitCode = 0;
  } else {
    console.log(`incorrect flag for ${slug}`);
    process.exitCode = 1;
  }
}
