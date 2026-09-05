// SPDX-License-Identifier: MIT
import { createHmac, timingSafeEqual } from 'node:crypto';

const FLAG_VERSION = 'v1';

/** FLAG{ hmac_sha256(secret, "v1|" + slug) } — matches every lab's entrypoint.sh. */
export function deriveFlag(secret: string, slug: string): string {
  const digest = createHmac('sha256', secret).update(`${FLAG_VERSION}|${slug}`).digest('hex');
  return `FLAG{${digest}}`;
}

export function verifyFlag(secret: string, slug: string, guess: string): boolean {
  const expected = Buffer.from(deriveFlag(secret, slug));
  const actual = Buffer.from(guess.trim());
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}
