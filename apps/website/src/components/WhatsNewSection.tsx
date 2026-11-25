import { ArrowUpRight, CheckCircle2, GitCompare } from 'lucide-react';
import {
  whatsNewHighlights,
  DOCS_BLOB_BASE,
  REPO_URL,
  type AccentTone,
} from '@/content/home';

const BADGE_STYLES: Record<AccentTone, string> = {
  indigo: 'border-indigo-400/35 bg-indigo-500/15 text-indigo-200',
  violet: 'border-violet-400/35 bg-violet-500/15 text-violet-200',
  cyan: 'border-cyan-400/35 bg-cyan-500/15 text-cyan-200',
  fuchsia: 'border-fuchsia-400/35 bg-fuchsia-500/15 text-fuchsia-200',
  emerald: 'border-emerald-400/35 bg-emerald-500/15 text-emerald-200',
  amber: 'border-amber-400/35 bg-amber-500/15 text-amber-200',
};

export function WhatsNewSection() {
  return (
    <section
      id="whats-new"
      aria-labelledby="whats-new-heading"
      className="scroll-mt-20 border-t border-white/[0.07] bg-white/[0.015] py-20 sm:py-28"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div className="max-w-3xl">
            <p className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-amber-300">
              Release Highlights · v4.0.1
            </p>
            <h2
              id="whats-new-heading"
              className="mt-2 text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-[2.6rem]"
            >
              Unified Flat Design System &amp; v4.0.1 hardening
            </h2>
            <p className="mt-3 text-base leading-relaxed text-slate-300">
              Builds on v4.0.0&apos;s pure-Rust control plane and Peer Clustering over <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-cyan-200">afpeer0</code> with a crisp 3-tier flat WASM UI, Debian 13 installer smoothness, Apache2 ingress/TLS sync, Jellyfin retries, and smarter peer endpoint detection.
            </p>
          </div>

          <div className="flex flex-wrap gap-2.5">
            <a
              href={`${DOCS_BLOB_BASE}/CHANGELOG.md`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-amber-400/45 hover:text-white"
            >
              <span>Full CHANGELOG.md</span>
              <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
            </a>
            <a
              href={`${REPO_URL}/compare/v4.0.0...v4.0.1`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-xl border border-indigo-400/35 bg-indigo-500/12 px-4 py-2 text-sm font-medium text-indigo-100 transition-colors hover:bg-indigo-500/20"
            >
              <GitCompare className="h-4 w-4" aria-hidden="true" />
              <span>v4.0.0...v4.0.1 diff</span>
            </a>
          </div>
        </div>

        <div className="mt-12 grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3">
          {whatsNewHighlights.map((item) => (
            <article
              key={item.title}
              className="obs-glass flex flex-col justify-between rounded-2xl p-6"
            >
              <div>
                <span
                  className={`inline-flex rounded-full border px-2.5 py-0.5 font-mono text-[11px] font-semibold ${BADGE_STYLES[item.tone]}`}
                >
                  {item.badge}
                </span>
                <h3 className="mt-3.5 text-lg font-bold tracking-tight text-white">
                  {item.title}
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-300">
                  {item.summary}
                </p>
                <ul className="mt-4 space-y-2 border-t border-white/[0.06] pt-4 text-xs leading-relaxed text-slate-300">
                  {item.bullets.map((bullet) => (
                    <li key={bullet} className="flex items-start gap-2">
                      <CheckCircle2
                        className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400"
                        aria-hidden="true"
                      />
                      <span>{bullet}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
