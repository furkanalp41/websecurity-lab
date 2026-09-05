// SPDX-License-Identifier: MIT
import type { Metadata } from 'next';
import { Geist_Mono, Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { MatrixRain } from '@/lib/matrix-rain';
import { TopBar } from '@/components/top-bar';
import { CommandPalette } from '@/components/command-palette';

const geistMono = Geist_Mono({ subsets: ['latin'], variable: '--font-geist-mono' });
const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });
const jetbrains = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jetbrains' });

export const metadata: Metadata = {
  title: 'WebSecurity Lab',
  description:
    'Self-hosted, gamified web-security CTF platform — 541 labs, one rabbit, one carrot.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark">
      <body className={`${geistMono.variable} ${inter.variable} ${jetbrains.variable}`}>
        <MatrixRain />
        <CommandPalette />
        <div style={{ position: 'relative', zIndex: 10 }}>
          <TopBar />
          <main style={{ maxWidth: 1200, margin: '0 auto', padding: 'var(--space-6)' }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
