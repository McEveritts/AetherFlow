import type { Metadata, Viewport } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { AuthProvider } from '@/contexts/AuthContext';
import AuthGuard from '@/components/layout/AuthGuard';

import { WebSocketProvider } from '@/contexts/WebSocketContext';

import { ToastProvider } from '@/contexts/ToastContext';
import ToastContainer from '@/components/layout/ToastContainer';
import NotificationDrawer from '@/components/layout/NotificationDrawer';
import ThemeProvider from '@/components/layout/ThemeProvider';
import LanguageProvider from '@/components/layout/LanguageProvider';
import PwaRegistry from '@/components/layout/PwaRegistry';
import SWRProvider from '@/components/layout/SWRProvider';
import { GlobalCommandPalette } from '@/components/layout/GlobalCommandPalette';

const inter = Inter({ subsets: ['latin'] })

export const viewport: Viewport = {
  themeColor: '#020617',
  width: 'device-width',
  initialScale: 1,
  viewportFit: 'cover',
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
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-[100] focus:px-4 focus:py-2 focus:rounded-lg focus:bg-indigo-600 focus:text-white focus:text-sm focus:font-semibold focus:shadow-lg"
        >
          Skip to main content
        </a>
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
          <GlobalCommandPalette />
          <ToastContainer />
          <NotificationDrawer />
        </ToastProvider>
        </LanguageProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
