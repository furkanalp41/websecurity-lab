// SPDX-License-Identifier: MIT
/**
 * build-catalog.ts — discover every labs/<track>/<slug>/meta.json, validate it
 * against labctl/src/schemas/meta.schema.json, cross-reference it against the
 * authoritative data/catalog.json, and emit data/catalog.generated.json (the
 * runtime index the hub and labctl consume).
 *
 * Exits non-zero on: schema violation, duplicate lab id among discovered labs,
 * an OWASP/CWE value outside packages/schema/enums.json, a lab id absent from
 * data/catalog.json, or a track/category mismatch. Emits a loud WARNING (but
 * does not fail) for duplicate slugs in the source catalog, since fixing those
 * requires an AUDITOR-approved charter update.
 */
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

const ROOT = join(import.meta.dirname, '..');
const LABS_DIR = join(ROOT, 'labs');
const CATALOG = join(ROOT, 'data', 'catalog.json');
const SCHEMA = join(ROOT, 'labctl', 'src', 'schemas', 'meta.schema.json');
const ENUMS = join(ROOT, 'packages', 'schema', 'enums.json');
const OUT = join(ROOT, 'data', 'catalog.generated.json');

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function fail(msg: string): never {
  console.error(`ERROR: ${msg}`);
  process.exit(1);
}

interface CatalogLab {
  slug: string;
  title: string;
  difficulty: string;
}
interface CatalogGroup {
  category: string;
  count: number;
  labs: CatalogLab[];
}
interface Meta {
  id: string;
  title: string;
  track: string;
  difficulty: string;
  owasp_categories: string[];
  cwe_ids: string[];
  [k: string]: unknown;
}

// ---- load authoritative catalog + build slug -> category index ----
const catalog = readJson(CATALOG) as CatalogGroup[];
const slugToCategory = new Map<string, string>();
const slugCounts = new Map<string, number>();
let catalogTotal = 0;
for (const group of catalog) {
  for (const lab of group.labs) {
    catalogTotal += 1;
    slugCounts.set(lab.slug, (slugCounts.get(lab.slug) ?? 0) + 1);
    if (!slugToCategory.has(lab.slug)) slugToCategory.set(lab.slug, group.category);
  }
}
console.log(`catalog: ${catalogTotal} labs across ${catalog.length} categories`);

const dupSlugs = [...slugCounts.entries()].filter(([, n]) => n > 1).map(([s]) => s);
if (dupSlugs.length > 0) {
  console.warn(
    `WARNING: duplicate slug(s) in data/catalog.json (needs a charter fix before those tracks ship): ${dupSlugs.join(', ')}`,
  );
}

// ---- compile schema + enums ----
const enums = readJson(ENUMS) as {
  owasp_top10_2021: string[];
  owasp_api_top10_2023: string[];
  cwe: string[];
};
const owaspSet = new Set([...enums.owasp_top10_2021, ...enums.owasp_api_top10_2023]);
const cweSet = new Set(enums.cwe);

// ajv-formats and ajv 2020 default-export interop under esbuild/tsx.
const AjvCtor = (Ajv2020 as unknown as { default?: typeof Ajv2020 }).default ?? Ajv2020;
const addFmt = (addFormats as unknown as { default?: typeof addFormats }).default ?? addFormats;
const ajv = new AjvCtor({ allErrors: true, strict: false });
addFmt(ajv);
const validate = ajv.compile(readJson(SCHEMA) as object);

// ---- discover labs/**/meta.json ----
function findMetaFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (entry.isFile() && entry.name === 'meta.json') {
      out.push(join(entry.parentPath ?? (entry as unknown as { path: string }).path, entry.name));
    }
  }
  return out;
}

const metaFiles = findMetaFiles(LABS_DIR).sort();
console.log(`discovered ${metaFiles.length} lab(s) under labs/`);

const seenIds = new Set<string>();
const generated: Array<Record<string, unknown>> = [];
let errors = 0;

for (const file of metaFiles) {
  const rel = file.slice(ROOT.length + 1);
  let meta: Meta;
  try {
    meta = readJson(file) as Meta;
  } catch (e) {
    console.error(`ERROR ${rel}: invalid JSON (${(e as Error).message})`);
    errors += 1;
    continue;
  }

  if (!validate(meta)) {
    console.error(`ERROR ${rel}: schema validation failed:`);
    for (const err of validate.errors ?? []) {
      console.error(`  - ${err.instancePath || '(root)'} ${err.message ?? ''}`);
    }
    errors += 1;
    continue;
  }

  if (seenIds.has(meta.id)) {
    console.error(`ERROR ${rel}: duplicate lab id "${meta.id}"`);
    errors += 1;
    continue;
  }
  seenIds.add(meta.id);

  // directory must match track
  const dirTrack = dirname(file)
    .slice(LABS_DIR.length + 1)
    .split('/')[0];
  if (dirTrack !== meta.track) {
    console.error(`ERROR ${rel}: track "${meta.track}" != directory "${dirTrack}"`);
    errors += 1;
  }

  // cross-reference against the authoritative catalog
  if (!slugToCategory.has(meta.id)) {
    console.error(`ERROR ${rel}: id "${meta.id}" is not a slug in data/catalog.json`);
    errors += 1;
  } else if (slugToCategory.get(meta.id) !== meta.track && slugCounts.get(meta.id) === 1) {
    console.error(
      `ERROR ${rel}: track "${meta.track}" != catalog category "${slugToCategory.get(meta.id)}"`,
    );
    errors += 1;
  }

  // enum membership
  for (const o of meta.owasp_categories) {
    if (!owaspSet.has(o)) {
      console.error(`ERROR ${rel}: owasp_categories value not in enums.json: "${o}"`);
      errors += 1;
    }
  }
  for (const c of meta.cwe_ids) {
    if (!cweSet.has(c)) {
      console.error(`ERROR ${rel}: cwe_ids value not in enums.json: "${c}"`);
      errors += 1;
    }
  }

  generated.push({
    id: meta.id,
    title: meta.title,
    track: meta.track,
    difficulty: meta.difficulty,
    estimated_minutes: meta.estimated_minutes,
    owasp_categories: meta.owasp_categories,
    cwe_ids: meta.cwe_ids,
    prerequisites: meta.prerequisites,
    tags: meta.tags ?? [],
    path: rel.replace(/\/meta\.json$/, ''),
  });
}

if (errors > 0) fail(`${errors} error(s) found; not writing ${OUT}`);

const output = {
  schema_version: '1.0.0',
  generated_from: 'labs/**/meta.json',
  catalog_total: catalogTotal,
  implemented: generated.length,
  labs: generated,
};
writeFileSync(OUT, JSON.stringify(output, null, 2) + '\n');
console.log(
  `OK: wrote ${OUT.slice(ROOT.length + 1)} (${generated.length} implemented / ${catalogTotal} planned)`,
);
