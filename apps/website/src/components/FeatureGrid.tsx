'use client';

import { useState } from 'react';
import {
  Activity,
  ArrowUpRight,
  Cpu,
  FolderLock,
  Globe,
  Layers,
  Network,
  Package,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import { features, type AccentTone } from '@/content/home';

interface FeatureGridProps {
  featureIcons: Record<string, string | null>;
}

const FEATURE_FALLBACK_ICONS: Record<string, LucideIcon> = {
  'rust-control-plane': Cpu,
  'leptos-wasm': Layers,
  marketplace: Package,
  'peer-clustering': Network,
  mcbrowser: FolderLock,
  streaming: Activity,
  flowai: Sparkles,
  networking: Globe,
  security: ShieldCheck,
  'self-update': RefreshCw,
};

const TONE_BADGE: Record<AccentTone, string> = {
  indigo: 'border-indigo-400/30 bg-indigo-500/12 text-indigo-300',
  violet: 'border-violet-400/30 bg-violet-500/12 text-violet-300',
  cyan: 'border-cyan-400/30 bg-cyan-500/12 text-cyan-300',
  fuchsia: 'border-fuchsia-400/30 bg-fuchsia-500/12 text-fuchsia-300',
  emerald: 'border-emerald-400/30 bg-emerald-500/12 text-emerald-300',
  amber: 'border-amber-400/30 bg-amber-500/12 text-amber-300',
};

const TONE_TAG: Record<AccentTone, string> = {
  indigo: 'text-indigo-300',
  violet: 'text-violet-300',
  cyan: 'text-cyan-300',
  fuchsia: 'text-fuchsia-300',
  emerald: 'text-emerald-300',
  amber: 'text-amber-300',
};

function FeatureIconTile({
  id,
  src,
  tone,
}: {
  id: string;
  src: string | null;
  tone: AccentTone;
}) {
  const [failed, setFailed] = useState(false);
  const Icon = FEATURE_FALLBACK_ICONS[id] ?? Cpu;

  return (
    <div
      className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border ${TONE_BADGE[tone]}`}
    >
      {src && !failed ? (
        <img
          src={src}
          alt=""
          width={32}
          height={32}
          onError={() => setFailed(true)}
          className="h-8 w-8 object-contain"
        />
      ) : (
        <Icon className="h-5 w-5" aria-hidden="true" />
      )}
    </div>
  );
}

export function FeatureGrid({ featureIcons }: FeatureGridProps) {
  return (
    <section
      id="features"
      aria-labelledby="features-heading"
      className="scroll-mt-20 py-20 sm:py-28"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="max-w-3xl">
          <p className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-indigo-300">
            Platform Capabilities
          </p>
          <h2
            id="features-heading"
            className="mt-2 text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-[2.6rem]"
          >
            Built for sovereign Linux hosts. Zero container theater.
          </h2>
          <p className="mt-4 text-base leading-relaxed text-slate-300 sm:text-lg">
            Every subsystem—from hardware telemetry and file confinement to peer WireGuard tunnels and atomic rollbacks—is compiled into memory-safe Rust binaries operating directly against systemd.
          </p>
        </div>

        <div className="mt-12 grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-2">
          {features.map((feature) => (
            <article
              key={feature.id}
              className="obs-glass group flex flex-col justify-between rounded-2xl p-6 transition-all duration-200 hover:-translate-y-0.5 hover:border-indigo-400/40 hover:shadow-[0_20px_48px_rgba(0,0,0,0.6),0_0_24px_rgba(99,102,241,0.16)]"
            >
              <div>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-center gap-3.5">
                    <FeatureIconTile
                      id={feature.id}
                      src={featureIcons[feature.id] ?? null}
                      tone={feature.tone}
                    />
                    <div>
                      <p className={`font-mono text-[11px] font-medium ${TONE_TAG[feature.tone]}`}>
                        {feature.tag}
                      </p>
                      <h3 className="mt-0.5 text-lg font-bold tracking-tight text-white">
                        {feature.title}
                      </h3>
                    </div>
                  </div>
                  <a
                    href={feature.docHref}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`Read documentation for ${feature.title}`}
                    className="rounded-lg border border-white/[0.08] bg-white/[0.03] p-2 text-slate-400 transition-colors hover:border-indigo-400/40 hover:text-white"
                  >
                    <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
                  </a>
                </div>

                <p className="mt-4 text-sm leading-relaxed text-slate-300">
                  {feature.summary}
                </p>
              </div>

              <div className="mt-5 flex flex-wrap gap-2 border-t border-white/[0.06] pt-4">
                {feature.specs.map((spec) => (
                  <span
                    key={spec}
                    className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 font-mono text-[11px] text-slate-300"
                  >
                    {spec}
                  </span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
