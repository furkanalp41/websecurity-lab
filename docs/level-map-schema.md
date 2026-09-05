# Level-Map Data Model & Layout Algorithm — 200+ Lab Skill Tree

## 1. Node JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://nullpath.dev/schemas/node.schema.json",
  "title": "SkillTreeNode",
  "type": "object",
  "required": [
    "id",
    "slug",
    "title",
    "category",
    "difficulty",
    "prereqs",
    "recommended",
    "track",
    "tier",
    "is_boss",
    "is_checkpoint"
  ],
  "additionalProperties": false,
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^n_[a-z0-9_]{3,48}$",
      "description": "Stable machine id (never renamed). Prefix 'n_' avoids collisions with tracks/edges."
    },
    "slug": {
      "type": "string",
      "pattern": "^[a-z0-9]+(?:-[a-z0-9]+)*$",
      "maxLength": 64,
      "description": "URL segment: /lab/<slug>. Human-editable, must be unique within track."
    },
    "title": { "type": "string", "minLength": 1, "maxLength": 80 },
    "category": {
      "type": "string",
      "enum": [
        "web",
        "crypto",
        "pwn",
        "reverse",
        "forensics",
        "network",
        "cloud",
        "mobile",
        "ai-ml",
        "meta"
      ]
    },
    "difficulty": {
      "type": "string",
      "enum": ["apprentice", "practitioner", "expert", "master"]
    },
    "prereqs": {
      "type": "array",
      "items": { "type": "string", "pattern": "^n_[a-z0-9_]{3,48}$" },
      "uniqueItems": true,
      "description": "Hard gates. All must be solved before this node unlocks."
    },
    "recommended": {
      "type": "array",
      "items": { "type": "string", "pattern": "^n_[a-z0-9_]{3,48}$" },
      "uniqueItems": true,
      "description": "Soft suggestions. Node is playable without these, but map shows a dashed edge."
    },
    "track": {
      "type": "string",
      "pattern": "^t_[a-z0-9_]{2,32}$",
      "description": "Track id (e.g., t_sqli). Drives column grouping in the layered layout."
    },
    "position": {
      "oneOf": [
        { "type": "null" },
        {
          "type": "object",
          "required": ["x", "y"],
          "additionalProperties": false,
          "properties": {
            "x": { "type": "number" },
            "y": { "type": "number" }
          }
        }
      ],
      "description": "null = auto-layout. Object = manual pin (overrides algorithm)."
    },
    "tier": {
      "type": "integer",
      "minimum": 0,
      "maximum": 12,
      "description": "Vertical rank. Layout groups all tier-N nodes on the same row. Bosses sit at tier boundary + 0.5 rendered offset."
    },
    "is_boss": { "type": "boolean" },
    "is_checkpoint": {
      "type": "boolean",
      "description": "Checkpoints save rabbit spawn location and gate downstream tiers (like Souls bonfires)."
    }
  },
  "allOf": [
    {
      "if": { "properties": { "is_boss": { "const": true } } },
      "then": { "properties": { "difficulty": { "enum": ["expert", "master"] } } }
    }
  ]
}
```

## 2. Edge JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://nullpath.dev/schemas/edge.schema.json",
  "title": "SkillTreeEdge",
  "type": "object",
  "required": ["from", "to", "kind"],
  "additionalProperties": false,
  "properties": {
    "from": { "type": "string", "pattern": "^n_[a-z0-9_]{3,48}$" },
    "to": { "type": "string", "pattern": "^n_[a-z0-9_]{3,48}$" },
    "kind": {
      "type": "string",
      "enum": ["prereq", "recommended", "optional-shortcut"],
      "description": "prereq = solid line, gate. recommended = dashed. optional-shortcut = dotted glowing (bypass path unlocked by boss kills)."
    }
  }
}
```

Edges are **derived** from `node.prereqs` and `node.recommended` at build time; `optional-shortcut` edges are the only ones authored directly (in a separate `shortcuts.json`) so they can be tuned without polluting the prereq DAG.

## 3. Layout Algorithm — Recommendation: **ELK `layered`**

**Verdict: ELK `layered` (elkjs)**, not Dagre, not `mrtree`.

**Why not `mrtree`:** the graph is a **DAG, not a tree**. A single node routinely has 2+ prereqs (e.g., "Blind SQLi over WebSocket" needs both `blind-sqli-boolean` and `websocket-injection`). `mrtree` forces a spanning-tree projection that either drops edges or duplicates nodes — both fatal for a skill map where the _point_ is showing convergence.

**Why not Dagre:** Dagre is dead upstream (last release 2020, known bugs with `rankdir=TB` + `ranker=network-simplex` on graphs >150 nodes: layer thrashing, crossing counts 3-5× ELK's). It also has no first-class support for **layer constraints**, which we need — `tier` in the schema must map to `layer` in the layout, and Dagre computes its own layers. Fighting Dagre to respect authored tiers means post-processing that undoes half its work.

**Why ELK `layered`:**

1. **Honors authored layers.** `elk.layered.layering.strategy: INTERACTIVE` + `layerConstraint: FIRST_SEPARATE|LAST_SEPARATE` on nodes lets `tier` win. Bosses can be pinned to tier boundaries.
2. **Track-aware columns.** `elk.layered.nodePlacement.strategy: NETWORK_SIMPLEX` combined with `partitioning.activate: true` and `partition = track_index` produces vertical bands per track — exactly the "column per skill family" visual we want.
3. **Real edge routing.** Orthogonal or spline edges with port constraints; edges enter nodes at top-center, exit at bottom-center, no crossings through node bodies.
4. **Stable.** Same input → same output (deterministic), critical because layout is cached in `map.generated.json` and diffed in CI.
5. **Manual override contract.** Any node with non-null `position` is pinned; ELK routes edges _to_ pinned coordinates without shifting them. Dagre cannot do this cleanly.

**Build-time pipeline (never runs in browser):**

```
scripts/build-map.ts
  1. Load catalog.json (all nodes + edges from prereqs/recommended)
  2. Validate against node/edge schemas (ajv) — fail build on schema errors
  3. Detect cycles in prereq DAG (fail build) — kahn's algorithm
  4. Detect unreachable nodes (no path from any tier-0 node) — warn
  5. Split into pinned (position != null) and auto nodes
  6. Feed auto nodes to elkjs with:
       algorithm: layered
       direction: DOWN
       layerConstraint: derived from tier
       partitioning.partition: derived from track index
       spacing.nodeNodeBetweenLayers: 120
       spacing.nodeNode: 80
       nodePlacement.strategy: NETWORK_SIMPLEX
       edgeRouting: ORTHOGONAL
  7. Merge pinned positions back on top of ELK output
  8. Emit map.generated.json with { nodes: [{id, x, y, w, h}], edges: [{from, to, kind, points: [{x,y}...]}], bounds: {minX, minY, maxX, maxY} }
  9. Emit map.generated.json.sha256 for cache-busting
```

Hub loads `map.generated.json` as a static asset. Zero layout math at runtime — only viewport transforms.

## 4. Camera Model

```ts
type Viewport = { x: number; y: number; zoom: number };

// State (Zustand or equivalent)
type CameraState = {
  viewport: Viewport; // authoritative
  target: Viewport | null; // spring destination when following
  userOverride: boolean; // true after any pan/pinch until recenter
  followNodeId: string | null; // rabbit's currentNode
};
```

**Follow behavior — soft spring** (critically-damped, no overshoot; users hate camera bounce on a map they're reading):

```ts
// Per-frame, in requestAnimationFrame
const STIFFNESS = 120; // higher = snappier
const DAMPING = 22; // 2*sqrt(STIFFNESS) ≈ critical damping
const dt = clampedFrameDelta();

if (!userOverride && followNodeId && target) {
  // Semi-implicit Euler spring
  velocity.x += (target.x - viewport.x) * STIFFNESS * dt;
  velocity.y += (target.y - viewport.y) * STIFFNESS * dt;
  velocity.x *= Math.exp(-DAMPING * dt);
  velocity.y *= Math.exp(-DAMPING * dt);
  viewport.x += velocity.x * dt;
  viewport.y += velocity.y * dt;
  // Zoom eases separately with lerp, not spring — no bounce on zoom
  viewport.zoom += (target.zoom - viewport.zoom) * (1 - Math.exp(-8 * dt));
}
```

**Interaction rules:**

- **Pan** (drag or two-finger scroll on mobile): sets `userOverride = true`, cancels spring.
- **Pinch / wheel-zoom**: zooms around pointer position (not viewport center), sets `userOverride = true`.
- **Recenter button** (bottom-right, always visible): clears `userOverride`, sets `target` to the rabbit's current node with `zoom = 1.0`.
- **Rabbit moves to new node**: if `userOverride` is false, `target` updates and spring pulls camera. If true, a subtle "Recenter" pulse animation plays on the button.
- **Zoom clamps**: `0.35 ≤ zoom ≤ 2.5`. Below 0.35, node labels are illegible; above 2.5, only ~3 nodes fit and users lose context.
- **Pan bounds**: viewport clamped to `bounds` from `map.generated.json` inflated by 200px margin — can't get lost in the void.

## 5. Progress Overlay (rendering contract)

Each node's render state is a pure function of `(node, playerProgress)`:

| State                                 | Visual                                                                                 |
| ------------------------------------- | -------------------------------------------------------------------------------------- |
| `solved`                              | Green glow ring (2px stroke `#22c55e`, 8px outer blur `#22c55e40`), full-opacity icon  |
| `current-attempt`                     | Pulsing amber ring (3px stroke `#f59e0b`, animated 0.6→1.0 opacity @ 1.2s ease-in-out) |
| `available` (unlocked, not attempted) | White 1.5px ring, 90% opacity icon                                                     |
| `locked`                              | Grey 1px ring `#3f3f46`, 40% opacity icon, padlock glyph bottom-right corner           |
| `boss` (any state)                    | Red outer ring (3px stroke `#dc2626`) _added to_ the state ring above                  |
| `checkpoint`                          | Small blue diamond glyph top-right corner, regardless of state                         |

Rings render as SVG `<circle>` overlays on top of the node sprite, so they're theme-independent and don't require re-baking node assets. The pulse animation is CSS `@keyframes` — no JS ticker, no jank when 200 nodes are visible.

State priority (only one ring at a time, plus the boss overlay): `current-attempt` > `solved` > `available` > `locked`.

## 6. Worked Example — 15-Node SQL Injection Track

Track `t_sqli` — apprentice → practitioner → expert → boss. `tier` runs 0-6. One checkpoint at tier 2 (after fundamentals), one boss at tier 6.

```json
{
  "track": {
    "id": "t_sqli",
    "title": "SQL Injection",
    "color": "#8b5cf6"
  },
  "nodes": [
    {
      "id": "n_sqli_intro",
      "slug": "sql-basics-refresher",
      "title": "SQL Basics Refresher",
      "category": "web",
      "difficulty": "apprentice",
      "prereqs": [],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 0,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_error_based",
      "slug": "error-based-sqli",
      "title": "Error-Based SQLi",
      "category": "web",
      "difficulty": "apprentice",
      "prereqs": ["n_sqli_intro"],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 1,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_union_basic",
      "slug": "union-based-sqli",
      "title": "UNION-Based Extraction",
      "category": "web",
      "difficulty": "apprentice",
      "prereqs": ["n_sqli_intro"],
      "recommended": ["n_sqli_error_based"],
      "track": "t_sqli",
      "position": null,
      "tier": 1,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_checkpoint_1",
      "slug": "sqli-fundamentals-checkpoint",
      "title": "Fundamentals Checkpoint",
      "category": "web",
      "difficulty": "apprentice",
      "prereqs": ["n_sqli_error_based", "n_sqli_union_basic"],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 2,
      "is_boss": false,
      "is_checkpoint": true
    },
    {
      "id": "n_sqli_blind_bool",
      "slug": "blind-sqli-boolean",
      "title": "Blind SQLi (Boolean)",
      "category": "web",
      "difficulty": "practitioner",
      "prereqs": ["n_sqli_checkpoint_1"],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 3,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_blind_time",
      "slug": "blind-sqli-time",
      "title": "Blind SQLi (Time-Based)",
      "category": "web",
      "difficulty": "practitioner",
      "prereqs": ["n_sqli_checkpoint_1"],
      "recommended": ["n_sqli_blind_bool"],
      "track": "t_sqli",
      "position": null,
      "tier": 3,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_second_order",
      "slug": "second-order-sqli",
      "title": "Second-Order SQLi",
      "category": "web",
      "difficulty": "practitioner",
      "prereqs": ["n_sqli_checkpoint_1"],
      "recommended": ["n_sqli_union_basic"],
      "track": "t_sqli",
      "position": null,
      "tier": 3,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_waf_bypass",
      "slug": "waf-bypass-encoding",
      "title": "WAF Bypass via Encoding",
      "category": "web",
      "difficulty": "practitioner",
      "prereqs": ["n_sqli_blind_bool"],
      "recommended": ["n_sqli_blind_time"],
      "track": "t_sqli",
      "position": null,
      "tier": 4,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_ws_injection",
      "slug": "sqli-over-websocket",
      "title": "SQLi over WebSocket",
      "category": "web",
      "difficulty": "practitioner",
      "prereqs": ["n_sqli_blind_bool"],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 4,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_nosql_pivot",
      "slug": "nosql-injection-pivot",
      "title": "NoSQL Injection Pivot",
      "category": "web",
      "difficulty": "expert",
      "prereqs": ["n_sqli_blind_bool", "n_sqli_second_order"],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 4,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_ordb_pg",
      "slug": "postgres-out-of-band",
      "title": "Postgres Out-of-Band Exfil",
      "category": "web",
      "difficulty": "expert",
      "prereqs": ["n_sqli_blind_time", "n_sqli_waf_bypass"],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 5,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_ordb_mssql",
      "slug": "mssql-xp-cmdshell",
      "title": "MSSQL xp_cmdshell to RCE",
      "category": "web",
      "difficulty": "expert",
      "prereqs": ["n_sqli_waf_bypass"],
      "recommended": ["n_sqli_ws_injection"],
      "track": "t_sqli",
      "position": null,
      "tier": 5,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_polyglot",
      "slug": "sqli-polyglot-payloads",
      "title": "Polyglot Payload Craft",
      "category": "web",
      "difficulty": "expert",
      "prereqs": ["n_sqli_nosql_pivot", "n_sqli_waf_bypass"],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 5,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_chained_rce",
      "slug": "sqli-to-rce-chain",
      "title": "SQLi → RCE Chain (Multi-Stage)",
      "category": "web",
      "difficulty": "expert",
      "prereqs": ["n_sqli_ordb_pg", "n_sqli_ordb_mssql", "n_sqli_polyglot"],
      "recommended": [],
      "track": "t_sqli",
      "position": null,
      "tier": 5,
      "is_boss": false,
      "is_checkpoint": false
    },
    {
      "id": "n_sqli_boss_kingdom",
      "slug": "kingdom-of-queries-boss",
      "title": "BOSS: Kingdom of Queries",
      "category": "web",
      "difficulty": "master",
      "prereqs": ["n_sqli_chained_rce"],
      "recommended": ["n_sqli_ws_injection"],
      "track": "t_sqli",
      "position": null,
      "tier": 6,
      "is_boss": true,
      "is_checkpoint": false
    }
  ]
}
```

**Structure notes:**

- **Tier 0** — single entry (fundamentals refresher).
- **Tier 1** — two parallel apprentice labs (both required for checkpoint).
- **Tier 2** — checkpoint gates the entire practitioner tier; ELK will place it centered above the tier-3 fork.
- **Tier 3** — three practitioner labs branch off the checkpoint; boolean-blind becomes the connective tissue.
- **Tier 4** — practitioner→expert transition, WAF bypass depends on blind-bool.
- **Tier 5** — expert labs converge; `chained_rce` requires three tier-5 nodes (perfect DAG convergence, would break `mrtree`).
- **Tier 6** — boss, gated by the convergence node; recommends WebSocket lab as an optional angle without gating.

At build time, ELK emits this as three visual columns (loosely: extraction / blind / out-of-band) collapsing into the boss at the bottom, with checkpoint as a horizontal separator across tier 2.
