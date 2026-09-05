'use client';
// SPDX-License-Identifier: MIT
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { MapEdge, MapNode } from '@/lib/catalog-data';
import { TIER_COLOR, TIER_LABEL, trackLabel } from '@/lib/tiers';

const R = 30; // hex radius in world units
const MIN_ZOOM = 0.35;
const MAX_ZOOM = 2.5;
const CULL_MARGIN = 240;
const SOLVED_KEY = 'websec-lab:solved';

type NodeState = 'solved' | 'available' | 'locked';

function hexPoints(r: number): string {
  // flat-top hexagon
  const pts: string[] = [];
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 180) * (60 * i + 30);
    pts.push(`${(r * Math.cos(a)).toFixed(2)},${(r * Math.sin(a)).toFixed(2)}`);
  }
  return pts.join(' ');
}
const HEX = hexPoints(R);

function readSolved(): Set<string> {
  try {
    const raw = localStorage.getItem(SOLVED_KEY);
    if (!raw) return new Set();
    return new Set(JSON.parse(raw) as string[]);
  } catch {
    return new Set();
  }
}

export function LevelMap({
  width,
  height,
  nodes,
  edges,
}: {
  width: number;
  height: number;
  nodes: MapNode[];
  edges: MapEdge[];
}) {
  const router = useRouter();
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState({ w: 1000, h: 700 });
  const [cam, setCam] = useState({ x: 0, y: 0, zoom: 0.5 });
  const [solved, setSolved] = useState<Set<string>>(new Set());
  const [focus, setFocus] = useState<string | null>(null);
  const [trackFilter, setTrackFilter] = useState<string>('all');
  const [showSummary, setShowSummary] = useState(false);
  const dragging = useRef<{ px: number; py: number; ox: number; oy: number } | null>(null);

  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const tracks = useMemo(() => Array.from(new Set(nodes.map((n) => n.track))), [nodes]);

  // prereqs from incoming edges
  const prereqs = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const e of edges) {
      const arr = m.get(e.to) ?? [];
      arr.push(e.from);
      m.set(e.to, arr);
    }
    return m;
  }, [edges]);

  const stateOf = useCallback(
    (id: string): NodeState => {
      if (solved.has(id)) return 'solved';
      const reqs = prereqs.get(id) ?? [];
      if (reqs.length === 0 || reqs.every((r) => solved.has(r))) return 'available';
      return 'locked';
    },
    [solved, prereqs],
  );

  useEffect(() => setSolved(readSolved()), []);

  // measure + fit on mount
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const cr = entries[0]?.contentRect;
      if (cr) setSize({ w: cr.width, h: cr.height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const fit = useCallback(() => {
    if (!width || !height) return;
    const z = Math.max(MIN_ZOOM, Math.min(size.w / (width + 120), size.h / (height + 120)));
    setCam({ x: (size.w - width * z) / 2, y: 24, zoom: z });
  }, [width, height, size]);

  const didFit = useRef(false);
  useEffect(() => {
    if (!didFit.current && size.w > 1) {
      didFit.current = true;
      fit();
    }
  }, [size, fit]);

  // wheel zoom around pointer
  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    setCam((c) => {
      const rect = wrapRef.current?.getBoundingClientRect();
      const px = e.clientX - (rect?.left ?? 0);
      const py = e.clientY - (rect?.top ?? 0);
      const factor = Math.exp(-e.deltaY * 0.0015);
      const z = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, c.zoom * factor));
      const k = z / c.zoom;
      return { zoom: z, x: px - (px - c.x) * k, y: py - (py - c.y) * k };
    });
  }, []);

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      if ((e.target as Element).closest('[data-node]')) return; // node handles its own
      dragging.current = { px: e.clientX, py: e.clientY, ox: cam.x, oy: cam.y };
      (e.currentTarget as Element).setPointerCapture(e.pointerId);
    },
    [cam],
  );
  const onPointerMove = useCallback((e: React.PointerEvent) => {
    const d = dragging.current;
    if (!d) return;
    setCam((c) => ({ ...c, x: d.ox + (e.clientX - d.px), y: d.oy + (e.clientY - d.py) }));
  }, []);
  const onPointerUp = useCallback(() => {
    dragging.current = null;
  }, []);

  const zoomBy = useCallback(
    (f: number) => {
      setCam((c) => {
        const z = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, c.zoom * f));
        const cx = size.w / 2;
        const cy = size.h / 2;
        const k = z / c.zoom;
        return { zoom: z, x: cx - (cx - c.x) * k, y: cy - (cy - c.y) * k };
      });
    },
    [size],
  );

  const centerOn = useCallback(
    (n: MapNode) => {
      setCam((c) => ({ ...c, x: size.w / 2 - n.x * c.zoom, y: size.h / 2 - n.y * c.zoom }));
    },
    [size],
  );

  const visibleNodes = useMemo(() => {
    const left = (-cam.x - CULL_MARGIN) / cam.zoom;
    const top = (-cam.y - CULL_MARGIN) / cam.zoom;
    const right = (size.w - cam.x + CULL_MARGIN) / cam.zoom;
    const bottom = (size.h - cam.y + CULL_MARGIN) / cam.zoom;
    return nodes.filter(
      (n) =>
        (trackFilter === 'all' || n.track === trackFilter) &&
        n.x >= left &&
        n.x <= right &&
        n.y >= top &&
        n.y <= bottom,
    );
  }, [nodes, cam, size, trackFilter]);

  const openNode = useCallback((n: MapNode) => router.push(`/lab/${n.track}/${n.slug}`), [router]);

  // keyboard: arrows move focus to nearest node in direction; enter opens; +/-/0 zoom/fit
  const moveFocus = useCallback(
    (dx: number, dy: number) => {
      const pool = nodes.filter((n) => trackFilter === 'all' || n.track === trackFilter);
      const cur = focus ? byId.get(focus) : undefined;
      const origin = cur ?? pool[0];
      if (!origin) return;
      let best: MapNode | null = null;
      let bestScore = Infinity;
      for (const n of pool) {
        if (n.id === origin.id) continue;
        const vx = n.x - origin.x;
        const vy = n.y - origin.y;
        if (vx * dx + vy * dy <= 0) continue; // wrong direction
        const along = Math.abs(vx * dx + vy * dy);
        const perp = Math.abs(vx * dy - vy * dx);
        const score = along + perp * 2;
        if (score < bestScore) {
          bestScore = score;
          best = n;
        }
      }
      if (best) {
        setFocus(best.id);
        centerOn(best);
      } else if (!cur) {
        setFocus(origin.id);
        centerOn(origin);
      }
    },
    [nodes, focus, byId, trackFilter, centerOn],
  );

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      switch (e.key) {
        case 'ArrowRight':
          e.preventDefault();
          moveFocus(1, 0);
          break;
        case 'ArrowLeft':
          e.preventDefault();
          moveFocus(-1, 0);
          break;
        case 'ArrowDown':
          e.preventDefault();
          moveFocus(0, 1);
          break;
        case 'ArrowUp':
          e.preventDefault();
          moveFocus(0, -1);
          break;
        case 'Enter':
        case ' ': {
          e.preventDefault();
          const n = focus ? byId.get(focus) : undefined;
          if (n) openNode(n);
          break;
        }
        case '+':
        case '=':
          e.preventDefault();
          zoomBy(1.2);
          break;
        case '-':
          e.preventDefault();
          zoomBy(1 / 1.2);
          break;
        case '0':
          e.preventDefault();
          fit();
          break;
        default:
          break;
      }
    },
    [moveFocus, focus, byId, openNode, zoomBy, fit],
  );

  const focusNode = focus ? byId.get(focus) : undefined;
  const showLabels = cam.zoom >= 0.5;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', flexWrap: 'wrap' }}
      >
        <h1 style={{ fontSize: 'var(--fs-lg)', margin: 0, letterSpacing: 'var(--tracking-tight)' }}>
          Level map
        </h1>
        <span style={{ color: 'var(--fg-subtle)', fontSize: 'var(--fs-xs)' }}>
          {nodes.length} nodes · {tracks.length} tracks · arrow keys to move, Enter to open
        </span>
        <label style={{ marginLeft: 'auto', color: 'var(--fg-muted)', fontSize: 'var(--fs-sm)' }}>
          Track{' '}
          <select
            value={trackFilter}
            onChange={(e) => setTrackFilter(e.target.value)}
            style={{
              background: 'var(--surface)',
              color: 'var(--fg)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--radius-sm)',
              padding: '2px 6px',
            }}
          >
            <option value="all">All tracks</option>
            {tracks.map((t) => (
              <option key={t} value={t}>
                {trackLabel(t)}
              </option>
            ))}
          </select>
        </label>
        <button type="button" onClick={() => setShowSummary((s) => !s)} className="mapbtn">
          {showSummary ? 'Hide' : 'Text'} map
        </button>
      </div>

      <div
        ref={wrapRef}
        role="application"
        aria-label="Skill map. Use arrow keys to move between labs and Enter to open the focused lab."
        aria-describedby="map-help"
        tabIndex={0}
        onKeyDown={onKeyDown}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        style={{
          position: 'relative',
          height: 'calc(100dvh - 200px)',
          minHeight: 420,
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
          background: 'var(--bg-sunken)',
          overflow: 'hidden',
          cursor: dragging.current ? 'grabbing' : 'grab',
          touchAction: 'none',
        }}
      >
        <p id="map-help" className="sr-only">
          Interactive skill map of {nodes.length} labs. Arrow keys move focus to the nearest lab in
          that direction; Enter opens the focused lab; plus and minus zoom; zero fits the whole map.
          A text alternative is available via the &quot;Text map&quot; button.
        </p>
        <svg width={size.w} height={size.h} role="presentation" style={{ display: 'block' }}>
          <g transform={`translate(${cam.x} ${cam.y}) scale(${cam.zoom})`}>
            {edges.map((e) => {
              const a = byId.get(e.from);
              const b = byId.get(e.to);
              if (!a || !b) return null;
              if (trackFilter !== 'all' && (a.track !== trackFilter || b.track !== trackFilter))
                return null;
              const powered = solved.has(e.from);
              return (
                <line
                  key={`${e.from}->${e.to}`}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={powered ? 'var(--accent)' : 'var(--border-strong)'}
                  strokeWidth={powered ? 2 : 1.5}
                  strokeDasharray={powered ? undefined : '4 6'}
                  opacity={0.8}
                />
              );
            })}
            {visibleNodes.map((n) => {
              const st = stateOf(n.id);
              const ring = TIER_COLOR[n.tier] ?? 'var(--fg-muted)';
              const isFocus = n.id === focus;
              return (
                <g
                  key={n.id}
                  data-node
                  transform={`translate(${n.x} ${n.y})`}
                  onClick={() => {
                    setFocus(n.id);
                    openNode(n);
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  <polygon
                    points={HEX}
                    fill={st === 'solved' ? 'var(--accent-wash)' : 'var(--surface)'}
                    stroke={st === 'locked' ? 'var(--fg-subtle)' : ring}
                    strokeWidth={isFocus ? 4 : st === 'available' ? 2.5 : 1.5}
                    opacity={st === 'locked' ? 0.45 : 1}
                  />
                  {isFocus && (
                    <polygon
                      points={hexPoints(R + 6)}
                      fill="none"
                      stroke="var(--accent)"
                      strokeWidth={2}
                      opacity={0.9}
                    />
                  )}
                  {st === 'solved' && (
                    <text textAnchor="middle" dy="6" fontSize="22" fill="var(--accent)">
                      ✓
                    </text>
                  )}
                  {st === 'locked' && (
                    <text textAnchor="middle" dy="6" fontSize="16" fill="var(--fg-subtle)">
                      🔒
                    </text>
                  )}
                  {showLabels && (
                    <text
                      textAnchor="middle"
                      y={R + 14}
                      fontSize="11"
                      fill="var(--fg-muted)"
                      style={{ pointerEvents: 'none' }}
                    >
                      {n.title.length > 26 ? `${n.title.slice(0, 24)}…` : n.title}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>

        {/* HUD */}
        <div
          style={{
            position: 'absolute',
            right: 'var(--space-4)',
            bottom: 'var(--space-4)',
            display: 'flex',
            flexDirection: 'column',
            gap: 'var(--space-2)',
          }}
        >
          <button type="button" onClick={() => zoomBy(1.2)} aria-label="Zoom in" className="mapbtn">
            +
          </button>
          <button
            type="button"
            onClick={() => zoomBy(1 / 1.2)}
            aria-label="Zoom out"
            className="mapbtn"
          >
            −
          </button>
          <button type="button" onClick={fit} aria-label="Fit map" className="mapbtn">
            ⤢
          </button>
        </div>

        {/* SR live region for focus changes */}
        <div aria-live="polite" className="sr-only">
          {focusNode
            ? `Focused: ${focusNode.title}, ${trackLabel(focusNode.track)} track, ${
                TIER_LABEL[focusNode.tier] ?? focusNode.tier
              }, ${stateOf(focusNode.id)}.`
            : ''}
        </div>
      </div>

      {/* Accessible text alternative — real links, full non-visual traversal */}
      {showSummary && (
        <nav aria-label="Text map of all labs" style={{ marginTop: 'var(--space-3)' }}>
          {tracks
            .filter((t) => trackFilter === 'all' || t === trackFilter)
            .map((t) => (
              <details key={t} style={{ marginBottom: 'var(--space-2)' }}>
                <summary style={{ cursor: 'pointer', color: 'var(--accent)' }}>
                  {trackLabel(t)} ({nodes.filter((n) => n.track === t).length})
                </summary>
                <ul
                  style={{
                    listStyle: 'none',
                    paddingLeft: 'var(--space-4)',
                    margin: 'var(--space-2) 0',
                  }}
                >
                  {nodes
                    .filter((n) => n.track === t)
                    .map((n) => (
                      <li key={n.id}>
                        <a href={`/lab/${n.track}/${n.slug}`}>{n.title}</a>{' '}
                        <span style={{ color: 'var(--fg-subtle)', fontSize: 'var(--fs-xs)' }}>
                          · {TIER_LABEL[n.tier] ?? n.tier} · {stateOf(n.id)}
                        </span>
                      </li>
                    ))}
                </ul>
              </details>
            ))}
        </nav>
      )}
    </div>
  );
}
