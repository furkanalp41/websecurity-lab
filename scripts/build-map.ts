// SPDX-License-Identifier: MIT
/**
 * build-map.ts — derive the level-map graph from data/catalog.json (and, when
 * present, docs/tracks/*.yml charters), run an elkjs `layered` layout, and emit
 * data/map.generated.json plus a .sha256 sidecar. Rendering is a UI-phase task;
 * this only produces the data file.
 *
 * P0: no track charters exist yet, so nodes come straight from the catalog and
 * edges are a linear chain within each track (lab[i] -> lab[i+1]).
 */
import ELK from 'elkjs/lib/elk.bundled.js';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dirname, '..');
const CATALOG = join(ROOT, 'data', 'catalog.json');
const TRACKS_DIR = join(ROOT, 'docs', 'tracks');
const OUT = join(ROOT, 'data', 'map.generated.json');

const NODE_W = 96;
const NODE_H = 96;

interface CatalogLab {
  slug: string;
  title: string;
  difficulty: string;
}
interface CatalogGroup {
  category: string;
  labs: CatalogLab[];
}

const catalog = JSON.parse(readFileSync(CATALOG, 'utf8')) as CatalogGroup[];

// Note charter presence for later phases (not parsed yet in P0).
const charterCount = existsSync(TRACKS_DIR)
  ? readdirSync(TRACKS_DIR).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml')).length
  : 0;
if (charterCount > 0) console.log(`found ${charterCount} track charter file(s) (not parsed in P0)`);

interface ElkNode {
  id: string;
  width: number;
  height: number;
  labels: Array<{ text: string }>;
}
interface ElkEdge {
  id: string;
  sources: string[];
  targets: string[];
}

const nodeMeta = new Map<
  string,
  { track: string; title: string; difficulty: string; index: number }
>();
const children: ElkNode[] = [];
const edges: ElkEdge[] = [];

for (const group of catalog) {
  group.labs.forEach((lab, i) => {
    const id = lab.slug;
    if (nodeMeta.has(id)) return; // skip duplicate slugs; build-catalog warns about them
    nodeMeta.set(id, {
      track: group.category,
      title: lab.title,
      difficulty: lab.difficulty,
      index: i,
    });
    children.push({ id, width: NODE_W, height: NODE_H, labels: [{ text: lab.title }] });
    if (i > 0) {
      const prev = group.labs[i - 1]!.slug;
      edges.push({ id: `${prev}->${id}`, sources: [prev], targets: [id] });
    }
  });
}

const elk = new ELK();
const graph = {
  id: 'root',
  layoutOptions: {
    'elk.algorithm': 'layered',
    'elk.direction': 'DOWN',
    'elk.spacing.nodeNode': '48',
    'elk.layered.spacing.nodeNodeBetweenLayers': '80',
  },
  children,
  edges,
};

const laid = (await elk.layout(graph)) as {
  children?: Array<{ id: string; x?: number; y?: number }>;
  edges?: Array<{ id: string; sources: string[]; targets: string[] }>;
  width?: number;
  height?: number;
};

const nodes = (laid.children ?? []).map((n) => {
  const meta = nodeMeta.get(n.id)!;
  return {
    id: n.id,
    slug: n.id,
    track: meta.track,
    tier: meta.difficulty,
    title: meta.title,
    x: Math.round(n.x ?? 0),
    y: Math.round(n.y ?? 0),
  };
});

const output = {
  schema_version: '1.0.0',
  generated_from: 'data/catalog.json',
  width: Math.round(laid.width ?? 0),
  height: Math.round(laid.height ?? 0),
  node_count: nodes.length,
  edge_count: edges.length,
  nodes,
  edges: edges.map((e) => ({ from: e.sources[0], to: e.targets[0], kind: 'linear' })),
};

const json = JSON.stringify(output, null, 2) + '\n';
writeFileSync(OUT, json);
const sha = createHash('sha256').update(json).digest('hex');
writeFileSync(`${OUT}.sha256`, `${sha}  ${OUT.slice(ROOT.length + 1)}\n`);
console.log(
  `OK: wrote ${OUT.slice(ROOT.length + 1)} (${nodes.length} nodes, ${edges.length} edges) sha256=${sha.slice(0, 12)}…`,
);
