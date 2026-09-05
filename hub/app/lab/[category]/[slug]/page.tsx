// SPDX-License-Identifier: MIT
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Placeholder } from '@/components/placeholder';

interface GeneratedCatalog {
  labs?: Array<{ track: string; id: string }>;
}

export function generateStaticParams(): Array<{ category: string; slug: string }> {
  try {
    const p = join(process.cwd(), '..', 'data', 'catalog.generated.json');
    const data = JSON.parse(readFileSync(p, 'utf8')) as GeneratedCatalog;
    if (data.labs && data.labs.length > 0) {
      return data.labs.map((l) => ({ category: l.track, slug: l.id }));
    }
  } catch {
    // fall through to the reference lab
  }
  return [{ category: 'sqli', slug: 'sqli-login-bypass-basic' }];
}

export default async function LabPage({
  params,
}: {
  params: Promise<{ category: string; slug: string }>;
}) {
  const { category, slug } = await params;
  return (
    <Placeholder
      title={`${category} / ${slug}`}
      blurb="Lab brief, launch controls, hints, and flag submission will render here."
    />
  );
}
