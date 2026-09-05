// SPDX-License-Identifier: MIT
export function Placeholder({ title, blurb }: { title: string; blurb: string }) {
  return (
    <section>
      <h1 style={{ fontSize: 'var(--fs-xl)', letterSpacing: 'var(--tracking-tight)' }}>{title}</h1>
      <p style={{ color: 'var(--fg-muted)' }}>{blurb}</p>
      <p
        style={{ color: 'var(--fg-subtle)', fontSize: 'var(--fs-sm)', marginTop: 'var(--space-5)' }}
      >
        Coming in a later build phase.
      </p>
    </section>
  );
}
