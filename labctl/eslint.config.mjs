// SPDX-License-Identifier: MIT
import config from 'eslint-config-websec-lab';

export default [...config, { ignores: ['dist/**', 'node_modules/**'] }];
