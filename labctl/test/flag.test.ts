// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';
import { deriveFlag, verifyFlag } from '../src/util/flag.js';

const DEV_SECRET = '0'.repeat(64);
const SLUG = 'sqli-login-bypass-basic';
// Verified against the running container's entrypoint (php hash_hmac).
const KNOWN = 'FLAG{22dec2b2d9292c37e6b0ac62485aaf0f80b4687b31971f4d22236b4fc3d64ebd}';

describe('deriveFlag', () => {
  it('matches the container-side HMAC vector', () => {
    expect(deriveFlag(DEV_SECRET, SLUG)).toBe(KNOWN);
  });

  it('verifies a correct flag and rejects a wrong one', () => {
    expect(verifyFlag(DEV_SECRET, SLUG, KNOWN)).toBe(true);
    expect(verifyFlag(DEV_SECRET, SLUG, 'FLAG{deadbeef}')).toBe(false);
  });
});
