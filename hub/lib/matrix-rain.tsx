'use client';
// SPDX-License-Identifier: MIT
import { useEffect, useRef } from 'react';

/** Ambient green code-rain, ~6% density, fixed behind content. Respects prefers-reduced-motion. */
export function MatrixRain() {
  const ref = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const chars = '01<>{}[]/\\|!@#$%^&*()-+=abcdefghijklmnopqrstuvwxyz';
    const fontSize = 14;
    const step = fontSize * 3; // ~6% column density
    let cols: number[] = [];
    let raf = 0;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const n = Math.max(1, Math.floor(canvas.width / step));
      cols = Array.from({ length: n }, () => Math.random() * canvas.height);
    };
    resize();
    window.addEventListener('resize', resize);

    const draw = () => {
      ctx.fillStyle = 'rgba(5,7,10,0.08)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#00ff41';
      ctx.font = `${fontSize}px 'JetBrains Mono', monospace`;
      ctx.globalAlpha = 0.07;
      for (let i = 0; i < cols.length; i++) {
        const y = cols[i] ?? 0;
        const ch = chars[Math.floor(Math.random() * chars.length)] ?? '0';
        ctx.fillText(ch, i * step, y);
        cols[i] = y > canvas.height ? 0 : y + fontSize * (0.6 + Math.random() * 1.2);
      }
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(draw);
    };

    if (reduce) {
      ctx.fillStyle = '#05070a';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
    } else {
      raf = requestAnimationFrame(draw);
    }

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <canvas
      ref={ref}
      aria-hidden="true"
      style={{ position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none', opacity: 0.5 }}
    />
  );
}
