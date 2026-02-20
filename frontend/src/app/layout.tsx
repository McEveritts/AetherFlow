import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'MediaNexus | AetherFlow',
  description: 'Next-Generation Decoupled Dashboard',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} min-h-screen bg-slate-950 text-slate-50 antialiased selection:bg-blue-500/30`}>
        {/* Ambient Background Glows */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none z-[-1]">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-blue-600/10 blur-[100px] rounded-full translate-x-1/3 -translate-y-1/3" />
          <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-indigo-600/10 blur-[100px] rounded-full -translate-x-1/3 translate-y-1/3" />
        </div>
        {children}
      </body>
    </html>
  )
}
