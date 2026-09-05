'use client';
// SPDX-License-Identifier: MIT
// Global ⌘K / Ctrl-K palette. Uses a native <dialog> so focus-trapping and
// Escape-to-close are handled by the platform (a11y-correct, zero deps).
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

interface Item {
  label: string;
  href: string;
  hint: string;
}

const PAGES: Item[] = [
  { label: 'Level map', href: '/map', hint: 'page' },
  { label: 'Handbook', href: '/handbook', hint: 'page' },
  { label: 'Leaderboard', href: '/leaderboard', hint: 'page' },
  { label: 'Achievements', href: '/achievements', hint: 'page' },
  { label: 'Profile', href: '/profile', hint: 'page' },
  { label: 'Settings', href: '/settings', hint: 'page' },
  { label: 'About', href: '/about', hint: 'page' },
];

interface IndexLab {
  slug: string;
  title: string;
  track: string;
}

export function CommandPalette() {
  const router = useRouter();
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [items, setItems] = useState<Item[]>(PAGES);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);

  useEffect(() => {
    fetch('/labs-index.json')
      .then((r) => (r.ok ? (r.json() as Promise<IndexLab[]>) : []))
      .then((labs) => {
        setItems([
          ...PAGES,
          ...labs.map((l) => ({
            label: l.title,
            href: `/lab/${l.track}/${l.slug}`,
            hint: l.track,
          })),
        ]);
      })
      .catch(() => setItems(PAGES));
  }, []);

  const open = useCallback(() => {
    const d = dialogRef.current;
    if (d && !d.open) {
      setQuery('');
      setActive(0);
      d.showModal();
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        open();
      }
    };
    const onOpen = () => open();
    window.addEventListener('keydown', onKey);
    window.addEventListener('websec:cmdk', onOpen);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('websec:cmdk', onOpen);
    };
  }, [open]);

  const filtered = useMemo(() => {
    const s = query.trim().toLowerCase();
    const pool = s ? items.filter((i) => i.label.toLowerCase().includes(s)) : items;
    return pool.slice(0, 50);
  }, [items, query]);

  const go = useCallback(
    (item: Item | undefined) => {
      if (!item) return;
      dialogRef.current?.close();
      router.push(item.href);
    },
    [router],
  );

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, filtered.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      go(filtered[active]);
    }
  };

  return (
    <dialog
      ref={dialogRef}
      className="cmdk"
      aria-label="Command palette"
      onClick={(e) => {
        if (e.target === dialogRef.current) dialogRef.current.close();
      }}
    >
      <div style={{ padding: 'var(--space-3)' }} onKeyDown={onKeyDown}>
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          placeholder="Jump to lab, track, or docs..."
          aria-label="Search labs, tracks, and docs"
          role="combobox"
          aria-expanded="true"
          aria-controls="cmdk-list"
          aria-activedescendant={filtered.length > 0 ? `cmdk-opt-${active}` : undefined}
          autoComplete="off"
          spellCheck={false}
          style={{
            width: '100%',
            background: 'var(--bg-sunken)',
            color: 'var(--fg)',
            border: '1px solid var(--border-strong)',
            borderRadius: 'var(--radius-sm)',
            padding: 'var(--space-3)',
            fontFamily: 'var(--font-geist-mono), monospace',
          }}
        />
        <ul
          id="cmdk-list"
          role="listbox"
          aria-label="Results"
          style={{
            listStyle: 'none',
            margin: 'var(--space-2) 0 0',
            padding: 0,
            maxHeight: 360,
            overflowY: 'auto',
          }}
        >
          {filtered.map((item, i) => (
            <li
              key={`${item.href}:${i}`}
              id={`cmdk-opt-${i}`}
              role="option"
              aria-selected={i === active}
              onMouseEnter={() => setActive(i)}
              onClick={() => go(item)}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                gap: 'var(--space-3)',
                padding: 'var(--space-2) var(--space-3)',
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                background: i === active ? 'var(--surface-hover)' : 'transparent',
                color: i === active ? 'var(--fg)' : 'var(--fg-muted)',
              }}
            >
              <span>{item.label}</span>
              <span style={{ color: 'var(--fg-subtle)', fontSize: 'var(--fs-xs)' }}>
                {item.hint}
              </span>
            </li>
          ))}
          {filtered.length === 0 && (
            <li style={{ padding: 'var(--space-3)', color: 'var(--fg-subtle)' }}>No matches.</li>
          )}
        </ul>
      </div>
    </dialog>
  );
}
