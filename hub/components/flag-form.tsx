'use client';
// SPDX-License-Identifier: MIT
import { useEffect, useState } from 'react';
import { connect, getMode, request } from '@/lib/labctl-client';

const SOLVED_KEY = 'websec-lab:solved';
const FLAG_RE = /^FLAG\{[0-9a-f]{64}\}$/;

function markSolved(slug: string): void {
  try {
    const raw = localStorage.getItem(SOLVED_KEY);
    const set = new Set<string>(raw ? (JSON.parse(raw) as string[]) : []);
    set.add(slug);
    localStorage.setItem(SOLVED_KEY, JSON.stringify([...set]));
  } catch {
    /* storage unavailable — non-fatal */
  }
}

export function FlagForm({ slug }: { slug: string }) {
  const [mode, setMode] = useState<'connecting' | 'live' | 'static'>('connecting');
  const [flag, setFlag] = useState('');
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  const [shake, setShake] = useState(false);

  useEffect(() => {
    connect()
      .then(setMode)
      .catch(() => setMode('static'));
  }, []);

  const fail = (msg: string) => {
    setStatus({ ok: false, msg });
    setShake(true);
    setTimeout(() => setShake(false), 300);
  };

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus(null);
    const guess = flag.trim();
    if (getMode() === 'live') {
      try {
        const r = await request<{ ok: boolean; first_solve?: boolean }>('flag.submit', {
          slug,
          guess,
        });
        if (r.ok) {
          markSolved(slug);
          setStatus({ ok: true, msg: 'Flag accepted.' });
        } else {
          fail('Not the flag. Try again.');
        }
      } catch (err) {
        fail(`Submit failed: ${(err as Error).message}`);
      }
      return;
    }
    // static mode: validate the shape and store locally as unverified
    if (FLAG_RE.test(guess)) {
      markSolved(slug);
      setStatus({ ok: true, msg: 'Saved locally (unverified — run ./labctl serve to verify).' });
    } else {
      fail('Expected FLAG{64 hex}. Run ./labctl serve to verify against your machine key.');
    }
  }

  return (
    <form onSubmit={onSubmit} style={{ display: 'grid', gap: 'var(--space-2)', maxWidth: 520 }}>
      <label htmlFor="flag-input" style={{ color: 'var(--fg-muted)', fontSize: 'var(--fs-sm)' }}>
        Submit flag
        {mode === 'static' && (
          <span style={{ color: 'var(--danger)', marginLeft: 8 }}>· read-only mode</span>
        )}
      </label>
      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
        <input
          id="flag-input"
          value={flag}
          onChange={(e) => setFlag(e.target.value)}
          placeholder="flag{...}"
          autoComplete="off"
          spellCheck={false}
          style={{
            flex: 1,
            background: 'var(--surface)',
            color: 'var(--fg)',
            border: `1px solid ${status && !status.ok ? 'var(--error)' : 'var(--border-strong)'}`,
            borderRadius: 'var(--radius-sm)',
            padding: 'var(--space-3)',
            fontFamily: 'var(--font-jetbrains), monospace',
            transform: shake ? 'translateX(0)' : undefined,
            animation: shake ? 'flag-shake 0.3s' : undefined,
          }}
        />
        <button
          type="submit"
          style={{
            background: 'var(--accent)',
            color: 'var(--fg-inverse)',
            border: 'none',
            borderRadius: 'var(--radius-sm)',
            padding: 'var(--space-3) var(--space-4)',
            fontWeight: 700,
            cursor: 'pointer',
          }}
        >
          Submit flag
        </button>
      </div>
      <p
        aria-live="polite"
        style={{
          minHeight: 20,
          margin: 0,
          fontSize: 'var(--fs-sm)',
          color: status?.ok ? 'var(--accent)' : 'var(--danger)',
        }}
      >
        {status?.msg ?? ''}
      </p>
    </form>
  );
}
