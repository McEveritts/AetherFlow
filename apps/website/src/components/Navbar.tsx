'use client';

import { useState } from 'react';
import { Menu, X, ArrowUpRight } from 'lucide-react';
import { BrandMark } from './BrandMark';
import { navLinks, REPO_URL, RELEASES_URL } from '@/content/home';
import { withBasePath } from '@/lib/basePath';

function GitHubIcon({ className = 'h-4 w-4' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
      aria-hidden="true"
    >
      <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2Z" />
    </svg>
  );
}

export function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="sticky top-0 z-40 border-b border-white/[0.08] bg-[#07090e]/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-[1440px] items-center justify-between gap-4 px-4 sm:px-6 lg:px-10">
        <a
          href={withBasePath('/')}
          className="group inline-flex items-center gap-2.5 rounded-lg py-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
        >
          <BrandMark className="h-8 w-8 shrink-0 transition-transform duration-200 group-hover:scale-105" />
          <span className="text-base font-bold tracking-tight text-white sm:text-lg">
            AetherFlow
          </span>
          <span className="inline-flex rounded-full border border-indigo-400/35 bg-indigo-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-indigo-200">
            v4.0.0
          </span>
        </a>

        <nav
          aria-label="Primary"
          className="hidden items-center gap-1 lg:flex"
        >
          {navLinks.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-300 transition-colors hover:bg-white/[0.06] hover:text-white"
            >
              {item.label}
            </a>
          ))}
        </nav>

        <div className="hidden items-center gap-2.5 sm:flex">
          <a
            href={REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-3.5 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-indigo-400/40 hover:bg-white/[0.08] hover:text-white"
          >
            <GitHubIcon className="h-4 w-4" />
            <span>GitHub</span>
          </a>
          <a
            href={RELEASES_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-violet-600 px-3.5 py-2 text-sm font-semibold text-white shadow-[0_4px_20px_rgba(99,102,241,0.35)] transition-all hover:brightness-110"
          >
            <span>Releases</span>
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
          </a>
        </div>

        <button
          type="button"
          onClick={() => setMobileOpen((prev) => !prev)}
          aria-expanded={mobileOpen}
          aria-controls="mobile-nav-drawer"
          aria-label={mobileOpen ? 'Close navigation menu' : 'Open navigation menu'}
          className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04] text-slate-200 transition-colors hover:bg-white/[0.08] lg:hidden"
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {mobileOpen && (
        <div
          id="mobile-nav-drawer"
          className="border-t border-white/[0.08] bg-[#080b14]/95 px-4 pb-5 pt-3 backdrop-blur-2xl lg:hidden"
        >
          <nav aria-label="Mobile" className="flex flex-col gap-1">
            {navLinks.map((item) => (
              <a
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className="rounded-lg px-3 py-2.5 text-sm font-medium text-slate-200 transition-colors hover:bg-white/[0.06] hover:text-white"
              >
                {item.label}
              </a>
            ))}
          </nav>
          <div className="mt-4 flex flex-col gap-2 border-t border-white/[0.08] pt-4 sm:flex-row">
            <a
              href={REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-white/12 bg-white/[0.05] px-4 py-2.5 text-sm font-medium text-white"
            >
              <GitHubIcon className="h-4 w-4" />
              <span>View on GitHub</span>
            </a>
            <a
              href={RELEASES_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 px-4 py-2.5 text-sm font-semibold text-white"
            >
              <span>v4.0.0 Releases</span>
              <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
            </a>
          </div>
        </div>
      )}
    </header>
  );
}
