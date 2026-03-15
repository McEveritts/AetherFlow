import type { Metadata, Viewport } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { AuthProvider } from '@/contexts/AuthContext';
import AuthGuard from '@/components/layout/AuthGuard';

import { WebSocketProvider } from '@/contexts/WebSocketContext';

import { ToastProvider } from '@/contexts/ToastContext';
import ToastContainer from '@/components/layout/ToastContainer';
import ThemeProvider from '@/components/layout/ThemeProvider';
import LanguageProvider from '@/components/layout/LanguageProvider';
import PwaRegistry from '@/components/layout/PwaRegistry';
import SWRProvider from '@/components/layout/SWRProvider';
import { CommandPalette } from '@/components/ui/CommandPalette';

const inter = Inter({ subsets: ['latin'] })

export const viewport: Viewport = {
  themeColor: '#020617',
}

export const metadata: Metadata = {
  title: 'AetherFlow Dashboard',
  description: 'Next-Generation Decoupled Dashboard',
  manifest: '/manifest.json',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'default',
    title: 'AetherFlow',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.className} min-h-screen bg-slate-950 text-slate-50 antialiased selection:bg-blue-500/30`}>
        <ThemeProvider>
        <LanguageProvider>
        <PwaRegistry />
        <ToastProvider>
          <SWRProvider>
          <AuthProvider>
            <AuthGuard>
              <WebSocketProvider>
                {children}
              </WebSocketProvider>
            </AuthGuard>
          </AuthProvider>
          </SWRProvider>
          <CommandPalette />
          <ToastContainer />
        </ToastProvider>
        </LanguageProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
