// SPDX-License-Identifier: MIT
import { execFileSync } from 'node:child_process';
import { PROGRESS_DB_PATH, TOKEN_PATH } from '../util/paths.js';

function tryCmd(cmd: string, args: string[]): string | null {
  try {
    return execFileSync(cmd, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return null;
  }
}

/** Print an environment preflight and set a non-zero exit code if anything is missing. */
export function doctor(): void {
  const node = process.version;
  const nodeMajor = Number.parseInt(node.slice(1), 10);
  const docker = tryCmd('docker', ['version', '--format', '{{.Server.Version}}']);
  const compose = tryCmd('docker', ['compose', 'version', '--short']);
  const git = tryCmd('git', ['--version']);

  const checks: Array<[string, string | null, boolean]> = [
    ['node (>=24)', node, nodeMajor >= 24],
    ['docker engine', docker, docker !== null],
    ['docker compose v2', compose, compose !== null],
    ['git', git, git !== null],
  ];

  let ok = true;
  for (const [name, value, pass] of checks) {
    if (!pass) ok = false;
    console.log(`${pass ? 'OK ' : 'XX '} ${name.padEnd(18)} ${value ?? '(not found)'}`);
  }
  console.log('');
  console.log(`progress db : ${PROGRESS_DB_PATH}`);
  console.log(`daemon token: ${TOKEN_PATH}`);
  process.exitCode = ok ? 0 : 1;
}
