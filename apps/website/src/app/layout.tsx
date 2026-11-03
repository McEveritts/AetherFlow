import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AetherFlow v4.0.0 | Sovereign Bare-Metal Infrastructure & Rust Control Plane',
  description: 'AetherFlow is a single-binary 11-crate Rust (Axum + Tokio) control plane and embedded Next.js 16 (Obsidian V2) dashboard orchestrating 77 bare-metal Linux services, Native McBrowser, and human-gated FlowAI.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased font-sans">
        {children}
      </body>
    </html>
  );
}
