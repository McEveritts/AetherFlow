import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AetherFlow | Bare-Metal Infrastructure Orchestration',
  description: 'AetherFlow is a high-performance orchestration core and dashboard built entirely in pure Go and strictly-typed TypeScript.',
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
