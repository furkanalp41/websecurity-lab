import type { NextConfig } from 'next';
import { join } from 'node:path';

// Static export (for `labctl serve` and the GitHub Pages demo) when NEXT_STATIC=1;
// plain dev/server otherwise.
const isStatic = process.env.NEXT_STATIC === '1';

const nextConfig: NextConfig = {
  ...(isStatic ? { output: 'export' } : {}),
  images: { unoptimized: true },
  // Pin the workspace root — /home/vlad also holds a lockfile, which otherwise
  // makes Next infer the wrong root.
  outputFileTracingRoot: join(import.meta.dirname, '..'),
};

export default nextConfig;
