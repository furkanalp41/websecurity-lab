// SPDX-License-Identifier: MIT
export function notImplemented(name: string): void {
  console.error(`labctl ${name}: not yet implemented (scheduled for a later phase)`);
  process.exitCode = 0;
}
