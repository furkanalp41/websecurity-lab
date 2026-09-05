// SPDX-License-Identifier: MIT
import Link from 'next/link';

const LINES = [
  'Two hundred labs. One rabbit. One carrot. Own the stack.',
  'Recon. Enumerate. Exploit. Chain.',
  'The map is the game.',
];

export default function Home() {
  return (
    <section>
      <div
        style={{
          border: '1px solid var(--border-strong)',
          borderRadius: 'var(--radius-lg)',
          background: 'var(--surface)',
          padding: 'var(--space-6)',
          boxShadow: 'var(--shadow-2)',
        }}
      >
        <div style={{ color: 'var(--fg-subtle)', fontSize: 'var(--fs-xs)' }}>╭─ user@matrix ─╮</div>
        <h1
          style={{
            fontSize: 'var(--fs-2xl)',
            lineHeight: 'var(--lh-tight)',
            letterSpacing: 'var(--tracking-tight)',
            margin: 'var(--space-4) 0',
          }}
        >
          <span style={{ color: 'var(--accent)' }}>WebSecurity Lab</span>
        </h1>
        {LINES.map((l) => (
          <p key={l} style={{ color: 'var(--fg-muted)', margin: '2px 0' }}>
            &gt; {l}
            <span style={{ color: 'var(--accent)' }}>▋</span>
          </p>
        ))}
        <div style={{ marginTop: 'var(--space-6)' }}>
          <Link
            href="/map"
            style={{
              display: 'inline-block',
              background: 'var(--accent)',
              color: 'var(--fg-inverse)',
              padding: 'var(--space-3) var(--space-5)',
              borderRadius: 'var(--radius-sm)',
              fontWeight: 700,
            }}
          >
            Open the map
          </Link>
        </div>
      </div>
      <p
        style={{
          color: 'var(--fg-subtle)',
          marginTop: 'var(--space-5)',
          fontSize: 'var(--fs-sm)',
        }}
      >
        541 labs · 20 tracks · runs locally in Docker · free hints and solutions, forever.
      </p>
    </section>
  );
}
