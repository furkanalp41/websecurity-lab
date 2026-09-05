#!/usr/bin/env node
// SPDX-License-Identifier: MIT
import { Command } from 'commander';
import { doctor } from './commands/doctor.js';
import { notImplemented } from './commands/stub.js';
import { submit } from './commands/submit.js';

const program = new Command();
program.name('labctl').description('WebSecurity Lab control CLI').version('0.1.0');

program
  .command('serve')
  .description('start the local hub + WebSocket daemon')
  .action(() => notImplemented('serve'));
program
  .command('list')
  .alias('ls')
  .description('list catalog labs and running labs')
  .action(() => notImplemented('list'));
program
  .command('new-lab <track/slug>')
  .description('scaffold a new lab from the template')
  .action(() => notImplemented('new-lab'));
program
  .command('launch <slug>')
  .description('launch a lab container')
  .action(() => notImplemented('launch'));
program
  .command('stop <slug>')
  .description('stop a running lab container')
  .action(() => notImplemented('stop'));
program
  .command('submit <slug> <flag>')
  .description('verify a flag against your local key')
  .action((slug: string, flag: string) => submit(slug, flag));
program
  .command('lint [slug]')
  .description('validate a lab against the author contract')
  .action(() => notImplemented('lint'));
program
  .command('doctor')
  .description('environment preflight')
  .action(() => doctor());

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
