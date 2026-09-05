// SPDX-License-Identifier: MIT
// Server-only data access (runs at build time under `output: export`). Reads the
// authoritative catalog, the generated map layout, and per-lab hint files.
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(process.cwd(), '..');

export interface CatalogLab {
  slug: string;
  category: string;
  title: string;
  difficulty: string;
  description: string;
  objective: string;
  flag_hint: string;
  skills_taught: string[];
  tech_stack: string[];
  inspired_by: string;
}

export interface MapNode {
  id: string;
  slug: string;
  track: string;
  tier: string;
  title: string;
  x: number;
  y: number;
}
export interface MapEdge {
  from: string;
  to: string;
  kind: string;
}
export interface MapData {
  width: number;
  height: number;
  nodes: MapNode[];
  edges: MapEdge[];
}

interface CatalogGroup {
  category: string;
  labs: Array<Omit<CatalogLab, 'category'>>;
}

function readJson<T>(rel: string): T {
  return JSON.parse(readFileSync(join(REPO_ROOT, rel), 'utf8')) as T;
}

export function loadCatalog(): CatalogLab[] {
  const groups = readJson<CatalogGroup[]>('data/catalog.json');
  const out: CatalogLab[] = [];
  for (const g of groups) {
    for (const lab of g.labs) out.push({ ...lab, category: g.category });
  }
  return out;
}

export function loadLab(category: string, slug: string): CatalogLab | null {
  return loadCatalog().find((l) => l.category === category && l.slug === slug) ?? null;
}

/** Which catalog slugs have an on-disk implementation (labs/<cat>/<slug>/meta.json). */
export function implementedSlugs(): Set<string> {
  const labsDir = join(REPO_ROOT, 'labs');
  const out = new Set<string>();
  if (!existsSync(labsDir)) return out;
  for (const entry of readdirSync(labsDir, { withFileTypes: true, recursive: true })) {
    if (entry.isFile() && entry.name === 'meta.json') {
      const parent = entry.parentPath ?? (entry as unknown as { path: string }).path;
      out.add(parent.split('/').pop() ?? '');
    }
  }
  return out;
}

export function loadHints(category: string, slug: string): string[] {
  const dir = join(REPO_ROOT, 'labs', category, slug, 'hints');
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => /^\d+\.md$/.test(f))
    .sort()
    .map((f) => readFileSync(join(dir, f), 'utf8').trim());
}

export function loadMap(): MapData {
  try {
    const raw = readJson<MapData>('data/map.generated.json');
    return { width: raw.width, height: raw.height, nodes: raw.nodes, edges: raw.edges };
  } catch {
    return { width: 0, height: 0, nodes: [], edges: [] };
  }
}
