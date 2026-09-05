'use client';
// SPDX-License-Identifier: MIT
// Minimal client for the local labctl daemon (ws://127.0.0.1:5174). Falls back to
// "static" mode when no daemon answers within 1.5s (GitHub Pages demo / file://).
// The per-install bearer token is injected by `labctl serve` as window.__LABCTL_TOKEN__
// (that injection is a ui-phase-2 task); absent it, the connection simply degrades.

export type Mode = 'connecting' | 'live' | 'static';

const WS_URL = 'ws://127.0.0.1:5174';

interface Pending {
  resolve: (r: unknown) => void;
  reject: (e: Error) => void;
}

declare global {
  interface Window {
    __LABCTL_TOKEN__?: string;
  }
}

let ws: WebSocket | null = null;
let mode: Mode = 'connecting';
let connectPromise: Promise<Mode> | null = null;
const pending = new Map<string, Pending>();
let counter = 0;

function token(): string | undefined {
  return typeof window === 'undefined' ? undefined : window.__LABCTL_TOKEN__;
}

export function connect(): Promise<Mode> {
  if (connectPromise) return connectPromise;
  if (typeof window === 'undefined') return Promise.resolve('static');

  connectPromise = new Promise<Mode>((resolve) => {
    let settled = false;
    const finish = (m: Mode) => {
      if (settled) return;
      settled = true;
      mode = m;
      resolve(m);
    };

    let socket: WebSocket;
    try {
      const t = token();
      socket = t ? new WebSocket(WS_URL, [`bearer.${t}`]) : new WebSocket(WS_URL);
    } catch {
      finish('static');
      return;
    }
    ws = socket;
    const timer = setTimeout(() => finish('static'), 1500);

    socket.onopen = () => {
      clearTimeout(timer);
      finish('live');
      socket.send(JSON.stringify({ id: 'hello', op: 'session.hello' }));
    };
    socket.onerror = () => {
      clearTimeout(timer);
      finish('static');
    };
    socket.onclose = () => {
      if (mode === 'connecting') finish('static');
    };
    socket.onmessage = (ev: MessageEvent<string>) => {
      try {
        const msg = JSON.parse(ev.data) as {
          id?: string;
          ok: boolean;
          data?: unknown;
          error?: string;
        };
        if (msg.id && pending.has(msg.id)) {
          const p = pending.get(msg.id);
          pending.delete(msg.id);
          if (!p) return;
          if (msg.ok) p.resolve(msg.data);
          else p.reject(new Error(msg.error ?? 'error'));
        }
      } catch {
        /* ignore malformed frames */
      }
    };
  });
  return connectPromise;
}

export function getMode(): Mode {
  return mode;
}

export function request<T = unknown>(op: string, params?: unknown): Promise<T> {
  if (mode !== 'live' || !ws) {
    return Promise.reject(new Error('daemon not connected (static mode)'));
  }
  const id = `r${++counter}`;
  const socket = ws;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (r: unknown) => void, reject });
    socket.send(JSON.stringify({ id, op, params }));
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error('timeout'));
      }
    }, 8000);
  });
}
