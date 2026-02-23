import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { AuthProvider } from '@/contexts/AuthContext';
import AuthGuard from '@/components/layout/AuthGuard';

import { WebSocketProvider } from '@/contexts/WebSocketContext';

import { ToastProvider } from '@/contexts/ToastContext';
import ToastContainer from '@/components/layout/ToastContainer';

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'AetherFlow Dashboard',
  description: 'Next-Generation Decoupled Dashboard',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className={`${inter.className} min-h-screen bg-slate-950 text-slate-50 antialiased selection:bg-blue-500/30`}>
        {/* Ambient Background Glows */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none z-[-1]">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-blue-600/10 blur-[100px] rounded-full translate-x-1/3 -translate-y-1/3" />
          <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-indigo-600/10 blur-[100px] rounded-full -translate-x-1/3 translate-y-1/3" />
        </div>
        <ToastProvider>
          <AuthProvider>
            <AuthGuard>
              <WebSocketProvider>
                {children}
              </WebSocketProvider>
            </AuthGuard>
          </AuthProvider>
          <ToastContainer />
        </ToastProvider>
      </body>
    </html>
  )
}
