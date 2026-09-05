// SPDX-License-Identifier: MIT
import { homedir } from 'node:os';
import { join } from 'node:path';

export const LABCTL_DIR = join(homedir(), '.labctl');
export const WEBSEC_DIR = join(homedir(), '.websec-lab');
export const TOKEN_PATH = join(LABCTL_DIR, 'token');
export const USER_KEY_PATH = join(WEBSEC_DIR, 'user.key');
export const PROGRESS_DB_PATH = join(WEBSEC_DIR, 'progress.db');
