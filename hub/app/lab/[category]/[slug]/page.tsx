// SPDX-License-Identifier: MIT
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { FlagForm } from '@/components/flag-form';
import { loadCatalog, loadHints, loadLab, implementedSlugs } from '@/lib/catalog-data';
import { TIER_LABEL, trackLabel } from '@/lib/tiers';

export function generateStaticParams(): Array<{ category: string; slug: string }> {
  return loadCatalog().map((l) => ({ category: l.category, slug: l.slug }));
}

export default async function LabPage({
  params,
}: {
  params: Promise<{ category: string; slug: string }>;
}) {
  const { category, slug } = await params;
  const lab = loadLab(category, slug);
  if (!lab) notFound();
  const hints = loadHints(category, slug);
  const implemented = implementedSlugs().has(slug);

  return (
    <article style={{ maxWidth: 820, display: 'grid', gap: 'var(--space-5)' }}>
      <nav style={{ fontSize: 'var(--fs-sm)', color: 'var(--fg-subtle)' }}>
        <Link href="/map">map</Link> / {trackLabel(lab.category)} /{' '}
        <span style={{ color: 'var(--fg-muted)' }}>{lab.title}</span>
      </nav>

      <header style={{ display: 'grid', gap: 'var(--space-2)' }}>
        <h1 style={{ fontSize: 'var(--fs-xl)', margin: 0, letterSpacing: 'var(--tracking-tight)' }}>
          {lab.title}
        </h1>
        <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
          <Badge>{trackLabel(lab.category)}</Badge>
          <Badge>{TIER_LABEL[lab.difficulty] ?? lab.difficulty}</Badge>
          <Badge tone={implemented ? 'ok' : 'muted'}>{implemented ? 'Playable' : 'Roadmap'}</Badge>
        </div>
      </header>

      <Section title="Scenario">
        <p className="prose-inter" style={{ color: 'var(--fg-muted)' }}>
          {lab.description}
        </p>
      </Section>

      <Section title="Objective">
        <p className="prose-inter" style={{ color: 'var(--fg-muted)' }}>
          {lab.objective}
        </p>
        {lab.skills_taught?.length > 0 && (
          <ul style={{ color: 'var(--fg-muted)' }}>
            {lab.skills_taught.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Getting started">
        {implemented ? (
          <>
            <p style={{ color: 'var(--fg-muted)' }}>
              Launch the lab, then open the instance URL it prints:
            </p>
            <pre className="mono-code" style={preStyle}>
              ./labctl launch {lab.category}/{lab.slug}
            </pre>
          </>
        ) : (
          <p style={{ color: 'var(--fg-muted)' }}>
            This lab is on the roadmap — its container is not authored yet. The scenario and
            objective above describe the class of bug it will teach.
          </p>
        )}
        <p style={{ color: 'var(--fg-subtle)', fontSize: 'var(--fs-sm)' }}>{lab.flag_hint}</p>
      </Section>

      {hints.length > 0 && (
        <Section title="Hints (free)">
          {hints.map((h, i) => (
            <details key={i} style={{ marginBottom: 'var(--space-2)' }}>
              <summary style={{ cursor: 'pointer', color: 'var(--info)' }}>
                Reveal hint {i + 1} of {hints.length}
              </summary>
              <p
                className="prose-inter"
                style={{ color: 'var(--fg-muted)', marginTop: 'var(--space-2)' }}
              >
                {h}
              </p>
            </details>
          ))}
        </Section>
      )}

      <Section title="Flag">
        <FlagForm slug={lab.slug} />
      </Section>

      {lab.inspired_by && (
        <p style={{ color: 'var(--fg-subtle)', fontSize: 'var(--fs-xs)' }}>
          Inspired by: {lab.inspired_by}
        </p>
      )}
    </article>
  );
}

const preStyle: React.CSSProperties = {
  background: 'var(--bg-sunken)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  padding: 'var(--space-3)',
  overflowX: 'auto',
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <h2 style={{ fontSize: 'var(--fs-md)', margin: 0, color: 'var(--fg)' }}>{title}</h2>
      {children}
    </section>
  );
}

function Badge({
  children,
  tone = 'default',
}: {
  children: React.ReactNode;
  tone?: 'default' | 'ok' | 'muted';
}) {
  const color =
    tone === 'ok' ? 'var(--accent)' : tone === 'muted' ? 'var(--fg-subtle)' : 'var(--fg-muted)';
  return (
    <span
      style={{
        border: `1px solid var(--border-strong)`,
        borderRadius: 'var(--radius-pill)',
        padding: '2px 10px',
        fontSize: 'var(--fs-xs)',
        color,
      }}
    >
      {children}
    </span>
  );
}
