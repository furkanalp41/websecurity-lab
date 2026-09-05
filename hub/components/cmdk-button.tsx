'use client';
// SPDX-License-Identifier: MIT
export function CmdkButton() {
  return (
    <button
      type="button"
      onClick={() => window.dispatchEvent(new Event('websec:cmdk'))}
      aria-label="Open command palette (Control or Command + K)"
      title="Search — Ctrl/Cmd + K"
      style={{
        color: 'var(--fg-muted)',
        fontSize: 'var(--fs-xs)',
        background: 'var(--surface)',
        border: '1px solid var(--border-strong)',
        borderRadius: 'var(--radius-sm)',
        padding: '2px 8px',
        cursor: 'pointer',
      }}
    >
      ⌘K
    </button>
  );
}
