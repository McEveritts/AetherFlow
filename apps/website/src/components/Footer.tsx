import { ArrowUpRight, Shield } from 'lucide-react';
import { BrandMark } from './BrandMark';
import { footerColumns, DOCS_BLOB_BASE, REPO_URL, RELEASES_URL } from '@/content/home';

export function Footer() {
  return (
    <footer className="border-t border-white/[0.08] bg-[#05070c]/90">
      <div className="mx-auto max-w-[1440px] px-4 py-16 sm:px-6 lg:px-10">
        {/* Closing CTA Banner */}
        <div className="obs-glass-chromatic mb-14 flex flex-col justify-between gap-6 rounded-2xl p-6 sm:p-8 lg:flex-row lg:items-center">
          <div className="max-w-2xl">
            <p className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
              Sovereign Bare-Metal Control
            </p>
            <h2 className="mt-2 text-2xl font-bold tracking-tight text-white sm:text-3xl">
              Command your Linux servers without container bloat.
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-slate-300">
              Inspect the 12-crate Rust control plane, audit the Leptos WebAssembly dashboard, and deploy AetherFlow v4.0.1 under GPL-3.0.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <a
              href={REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-violet-600 px-5 py-3 text-sm font-semibold text-white shadow-[0_6px_24px_rgba(99,102,241,0.38)] transition-all hover:brightness-110"
            >
              <span>View Repository</span>
              <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
            </a>
            <a
              href={RELEASES_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-xl border border-white/15 bg-white/[0.05] px-5 py-3 text-sm font-semibold text-slate-100 transition-colors hover:border-cyan-400/45 hover:bg-white/[0.09]"
            >
              <span>v4.0.1 Releases</span>
              <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
            </a>
          </div>
        </div>

        {/* Footer Links Grid */}
        <div className="grid grid-cols-1 gap-10 md:grid-cols-2 lg:grid-cols-12">
          <div className="lg:col-span-4">
            <div className="flex items-center gap-2.5">
              <BrandMark className="h-8 w-8 shrink-0" />
              <span className="text-lg font-bold tracking-tight text-white">
                AetherFlow
              </span>
              <span className="rounded-full border border-indigo-400/35 bg-indigo-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-indigo-200">
                v4.0.1
              </span>
            </div>
            <p className="mt-4 max-w-sm text-sm leading-relaxed text-slate-400">
              Self-hosted bare-metal Linux infrastructure and media-server control plane built in Rust and Leptos WebAssembly.
            </p>
            <div className="mt-5 flex flex-wrap items-center gap-2">
              <a
                href={`${DOCS_BLOB_BASE}/LICENSE.md`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-400/30 bg-emerald-500/10 px-3 py-1.5 font-mono text-xs font-semibold text-emerald-300 transition-colors hover:bg-emerald-500/20"
              >
                <Shield className="h-3.5 w-3.5" aria-hidden="true" />
                <span>GPL-3.0 Licensed</span>
              </a>
              <a
                href={`${DOCS_BLOB_BASE}/SECURITY.md`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 font-mono text-xs text-slate-300 transition-colors hover:border-indigo-400/40 hover:text-white"
              >
                <span>SECURITY.md</span>
              </a>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-8 sm:grid-cols-3 lg:col-span-8">
            {footerColumns.map((col) => (
              <div key={col.heading}>
                <h3 className="font-mono text-xs font-semibold uppercase tracking-[0.16em] text-slate-300">
                  {col.heading}
                </h3>
                <ul className="mt-4 space-y-2.5">
                  {col.links.map((link) => (
                    <li key={link.label}>
                      <a
                        href={link.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-sm text-slate-400 transition-colors hover:text-white"
                      >
                        <span>{link.label}</span>
                        <ArrowUpRight
                          className="h-3 w-3 opacity-60"
                          aria-hidden="true"
                        />
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-12 flex flex-col items-start justify-between gap-3 border-t border-white/[0.07] pt-6 text-xs text-slate-500 sm:flex-row sm:items-center">
          <p>
            AetherFlow Contributors · Distributed under the GNU General Public License v3.0 (GPL-3.0).
          </p>
          <p className="font-mono text-[11px] text-slate-400">
            12-crate backend-rs · 4-crate frontend-rs · 77 native packages
          </p>
        </div>
      </div>
    </footer>
  );
}
