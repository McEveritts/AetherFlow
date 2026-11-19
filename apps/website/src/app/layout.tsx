import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AetherFlow v4.0.0 | Sovereign Bare-Metal Infrastructure & Rust Control Plane',
  description: 'AetherFlow v4.0.0 is a Rust control plane (backend-rs) and Leptos Rust WebAssembly dashboard (frontend-rs) orchestrating a 77-app bare-metal catalog, Native McBrowser (af-files), Zero-Sudo aetherflow-runner, Whatbox-style Subdomain Ingress, and human-gated FlowAI.',
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
