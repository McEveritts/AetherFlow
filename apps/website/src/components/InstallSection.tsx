'use client';

import { useState } from 'react';
import { ArrowUpRight, Check, Copy, Terminal } from 'lucide-react';
import { installCommands, DOCS_BLOB_BASE } from '@/content/home';

type InstallMode = 'interactive' | 'unattended';

export function InstallSection() {
  const [mode, setMode] = useState<InstallMode>('interactive');
  const [copiedMode, setCopiedMode] = useState<InstallMode | null>(null);

  const active = installCommands[mode];

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(active.command);
      setCopiedMode(mode);
      window.setTimeout(() => setCopiedMode(null), 2200);
    } catch {
      // Clipboard API unavailable in restricted contexts
    }
  }

  return (
    <section
      id="install"
      aria-labelledby="install-heading"
      className="scroll-mt-20 border-t border-white/[0.07] py-20 sm:py-28"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="grid grid-cols-1 gap-10 lg:grid-cols-12 lg:items-start">
          <div className="lg:col-span-5">
            <p className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-emerald-300">
              Quick Installation
            </p>
            <h2
              id="install-heading"
              className="mt-2 text-3xl font-bold tracking-tight text-white sm:text-4xl"
            >
              Deploy on clean Debian or Ubuntu in minutes
            </h2>
            <p className="mt-4 text-base leading-relaxed text-slate-300">
              Taken verbatim from <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-indigo-200">README.md</code>. Deploy on a clean <strong>Debian 12/13 (Bookworm/Trixie)</strong> or <strong>Ubuntu 22.04/24.04 LTS</strong> host with zero container daemon overhead.
            </p>

            <div className="mt-6 space-y-3 text-sm text-slate-300">
              <div className="obs-glass rounded-xl p-4">
                <div className="font-semibold text-white">
                  Fresh host vs. day-2 administration
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-400">
                  Use <code className="font-mono text-indigo-200">setup/AetherFlow-Setup</code> for fresh bare-metal host provisioning (APT repos, Apache2, TLS, initial onboarding). Use <code className="font-mono text-cyan-200">af provision</code> for repeatable Rust-native foundation steps on an installed host.
                </p>
              </div>
              <div className="obs-glass rounded-xl p-4">
                <div className="font-semibold text-white">
                  Upgrading an existing v3.2.x or v4.0.0 node?
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-400">
                  The isolated updater switches API binaries and matching <code className="font-mono text-indigo-200">web/dist</code> dashboard assets atomically while preserving the HTTP API and runner socket.
                </p>
                <div className="mt-3 flex flex-wrap gap-3">
                  <a
                    href={`${DOCS_BLOB_BASE}/docs/upgrading.md`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-cyan-300 hover:text-cyan-200"
                  >
                    <span>Upgrading &amp; Rollbacks</span>
                    <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </a>
                  <a
                    href={`${DOCS_BLOB_BASE}/docs/rust-admin-cli.md`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-indigo-300 hover:text-indigo-200"
                  >
                    <span>af CLI Reference</span>
                    <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </a>
                </div>
              </div>
            </div>
          </div>

          <div className="lg:col-span-7">
            <div className="obs-glass-chromatic overflow-hidden rounded-2xl">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] bg-[#060912]/90 px-4 py-3">
                <div
                  role="tablist"
                  aria-label="Installation modes"
                  className="inline-flex rounded-lg border border-white/10 bg-white/[0.03] p-0.5"
                >
                  <button
                    type="button"
                    role="tab"
                    aria-selected={mode === 'interactive'}
                    onClick={() => setMode('interactive')}
                    className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
                      mode === 'interactive'
                        ? 'bg-indigo-500/25 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {installCommands.interactive.label}
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={mode === 'unattended'}
                    onClick={() => setMode('unattended')}
                    className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
                      mode === 'unattended'
                        ? 'bg-indigo-500/25 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {installCommands.unattended.label}
                  </button>
                </div>

                <button
                  type="button"
                  onClick={handleCopy}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.06] px-3 py-1.5 font-mono text-xs font-medium text-slate-200 transition-colors hover:border-emerald-400/50 hover:text-white"
                >
                  {copiedMode === mode ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                      <span className="text-emerald-300">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Copy commands</span>
                    </>
                  )}
                </button>
              </div>

              <div className="p-5 sm:p-6">
                <div className="mb-3 flex items-center justify-between gap-2 font-mono text-[11px] text-slate-400">
                  <span className="inline-flex items-center gap-1.5 text-emerald-300">
                    <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
                    bash
                  </span>
                  <span>{active.badge}</span>
                </div>

                <pre className="obs-code-block obs-scroll overflow-x-auto rounded-xl p-4 text-xs leading-6 text-slate-100 sm:text-[13px]">
                  <code>{active.command}</code>
                </pre>

                <p className="mt-4 text-xs leading-relaxed text-slate-400">
                  {active.note}
                </p>

                <div className="sr-only" aria-live="polite">
                  {copiedMode === mode ? 'Install commands copied to clipboard.' : ''}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
