// SPDX-License-Identifier: MIT
import { LevelMap } from '@/components/level-map';
import { loadMap } from '@/lib/catalog-data';

export const metadata = { title: 'Level map · WebSecurity Lab' };

export default function MapPage() {
  const map = loadMap();
  if (map.nodes.length === 0) {
    return (
      <section>
        <h1 style={{ fontSize: 'var(--fs-xl)' }}>Level map</h1>
        <p style={{ color: 'var(--fg-muted)' }}>
          Map data not generated yet. Run <code>pnpm run map</code> (or{' '}
          <code>./scripts/bootstrap.sh</code>) to build <code>data/map.generated.json</code>.
        </p>
      </section>
    );
  }
  return <LevelMap width={map.width} height={map.height} nodes={map.nodes} edges={map.edges} />;
}
