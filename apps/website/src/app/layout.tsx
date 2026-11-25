import type { Metadata, Viewport } from 'next';
import './globals.css';
import { BASE_PATH, SITE_ORIGIN, withMediaPath } from '@/lib/basePath';

const title = 'AetherFlow v4.0.1 — Sovereign Bare-Metal Linux Control Plane in Rust';
const description =
  'AetherFlow v4.0.1 pairs a 12-crate Rust control plane (Axum + Tokio) with a 4-crate Leptos WebAssembly dashboard built on the Unified Flat Surface & Control System. Orchestrate 77 native systemd apps, Peer Clustering over afpeer0 WireGuard, Native McBrowser, canonical streaming analytics, and human-gated FlowAI.';

const canonicalPath = BASE_PATH ? `${BASE_PATH}/` : '/';
const socialImage = withMediaPath('social-preview.png');
const iconUrl = withMediaPath('brand/aetherflow-icon.svg');

export const metadata: Metadata = {
  metadataBase: new URL(SITE_ORIGIN),
  title,
  description,
  applicationName: 'AetherFlow',
  keywords: [
    'AetherFlow',
    'bare-metal Linux',
    'Rust control plane',
    'Leptos WebAssembly',
    'systemd',
    'Peer Clustering',
    'WireGuard',
    'Jellyfin transcoding',
    'McBrowser',
    'self-hosted media server',
  ],
  alternates: {
    canonical: canonicalPath,
  },
  openGraph: {
    type: 'website',
    siteName: 'AetherFlow',
    title,
    description,
    url: `${SITE_ORIGIN}${canonicalPath}`,
    images: [
      {
        url: socialImage,
        width: 1200,
        height: 630,
        alt: 'AetherFlow v4.0.1 — 12-Crate Rust Control Plane, Leptos WASM Dashboard, Peer Clustering & 77-App Bare-Metal Catalog',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title,
    description,
    images: [socialImage],
  },
  icons: {
    icon: [{ url: iconUrl, type: 'image/svg+xml' }],
  },
};

export const viewport: Viewport = {
  themeColor: '#07090e',
  colorScheme: 'dark',
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased selection:bg-indigo-500/30 selection:text-indigo-100">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:rounded-lg focus:bg-indigo-600 focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-white focus:shadow-lg"
        >
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
