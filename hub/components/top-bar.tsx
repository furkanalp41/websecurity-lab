// SPDX-License-Identifier: MIT
import Link from 'next/link';

const NAV: ReadonlyArray<readonly [string, string]> = [
  ['Map', '/map'],
  ['Handbook', '/handbook'],
  ['Leaderboard', '/leaderboard'],
  ['Achievements', '/achievements'],
];

export function TopBar() {
  return (
    <header
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 30,
        height: 56,
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--space-5)',
        padding: '0 var(--space-6)',
        background: 'color-mix(in srgb, var(--bg-elevated) 92%, transparent)',
        borderBottom: '1px solid var(--border)',
      }}
    >
      <Link
        href="/"
        style={{ color: 'var(--accent)', fontWeight: 700, letterSpacing: 'var(--tracking-tight)' }}
      >
        &gt;_rabbit
      </Link>
      <nav style={{ display: 'flex', gap: 'var(--space-4)' }}>
        {NAV.map(([label, href]) => (
          <Link key={href} href={href} style={{ color: 'var(--fg-muted)' }}>
            {label}
          </Link>
        ))}
      </nav>
      <span style={{ marginLeft: 'auto', color: 'var(--fg-subtle)', fontSize: 'var(--fs-xs)' }}>
        matrix // dark-only
      </span>
    </header>
  );
}
