'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  Copy,
  KeyRound,
  Lock,
  Network,
  Terminal,
} from 'lucide-react';
import {
  peerClusteringContent,
  DOCS_BLOB_BASE,
  type AccentTone,
} from '@/content/home';

interface PeerClusteringSectionProps {
  peerClusteringSvgSrc: string | null;
}

const TONE_ACCENT: Record<AccentTone, string> = {
  indigo: 'text-indigo-300 border-indigo-400/30 bg-indigo-500/12',
  violet: 'text-violet-300 border-violet-400/30 bg-violet-500/12',
  cyan: 'text-cyan-300 border-cyan-400/30 bg-cyan-500/12',
  fuchsia: 'text-fuchsia-300 border-fuchsia-400/30 bg-fuchsia-500/12',
  emerald: 'text-emerald-300 border-emerald-400/30 bg-emerald-500/12',
  amber: 'text-amber-300 border-amber-400/30 bg-amber-500/12',
};

function FallbackPeerTopologySvg() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1120 340"
      role="img"
      aria-label="AetherFlow Peer Clustering topology showing two independent Debian 13 hosts paired over an encrypted afpeer0 WireGuard tunnel carrying Peer API TCP 9443, NFSv4.2 media mounts TCP 2049, and af-transcode Jellyfin 12.4 jobs"
      className="h-auto w-full"
    >
      <defs>
        <linearGradient id="peerBg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#070a12" />
          <stop offset="100%" stopColor="#0c1224" />
        </linearGradient>
        <linearGradient id="tunnelStroke" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#22d3ee" />
          <stop offset="50%" stopColor="#6366f1" />
          <stop offset="100%" stopColor="#d946ef" />
        </linearGradient>
      </defs>

      <rect width="1120" height="340" rx="16" fill="url(#peerBg)" />

      {/* Left Server */}
      <rect x="28" y="34" width="330" height="272" rx="16" fill="#0d1426" stroke="#22d3ee" strokeOpacity="0.55" strokeWidth="1.5" />
      <text x="50" y="64" fill="#67e8f9" fontFamily="ui-monospace, monospace" fontSize="11" fontWeight="700">SERVER A · CONTROLLER / INITIATOR</text>
      <text x="50" y="92" fill="#ffffff" fontFamily="system-ui, sans-serif" fontSize="18" fontWeight="700">Sovereign Node (Debian 13)</text>
      <text x="50" y="116" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">afpeer0: 10.231.x.1 · UDP 51821</text>

      <rect x="50" y="136" width="286" height="44" rx="9" fill="#121b33" stroke="#6366f1" strokeOpacity="0.4" />
      <text x="64" y="156" fill="#e0e7ff" fontFamily="ui-monospace, monospace" fontSize="11.5" fontWeight="700">Header Active Server Switcher</text>
      <text x="64" y="172" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">Scoped proxy to peer API (8 grant areas)</text>

      <rect x="50" y="190" width="286" height="44" rx="9" fill="#121b33" stroke="#10b981" strokeOpacity="0.4" />
      <text x="64" y="210" fill="#d1fae5" fontFamily="ui-monospace, monospace" fontSize="11.5" fontWeight="700">/mnt/af-peers/&lt;link&gt;/&lt;export&gt;</text>
      <text x="64" y="226" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">NFSv4.2 mount + 15s .af-peer-sentinel</text>

      <rect x="50" y="244" width="286" height="44" rx="9" fill="#121b33" stroke="#d946ef" strokeOpacity="0.4" />
      <text x="64" y="264" fill="#f5d0fe" fontFamily="ui-monospace, monospace" fontSize="11.5" fontWeight="700">Jellyfin 12.4 + af-transcode shim</text>
      <text x="64" y="280" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">/usr/lib/aetherflow/transcode/ffmpeg</text>

      {/* Center WireGuard Tunnel */}
      <rect x="400" y="54" width="320" height="232" rx="16" fill="#090f1f" stroke="url(#tunnelStroke)" strokeWidth="2" strokeDasharray="6 4" />
      <text x="560" y="84" textAnchor="middle" fill="#67e8f9" fontFamily="ui-monospace, monospace" fontSize="12" fontWeight="700">DEDICATED WIREGUARD MESH</text>
      <text x="560" y="106" textAnchor="middle" fill="#ffffff" fontFamily="ui-monospace, monospace" fontSize="15" fontWeight="700">afpeer0 (10.231.0.0/16)</text>

      <rect x="424" y="124" width="272" height="38" rx="8" fill="#101830" stroke="#6366f1" strokeOpacity="0.45" />
      <text x="560" y="148" textAnchor="middle" fill="#c7d2fe" fontFamily="ui-monospace, monospace" fontSize="11.5">TCP 9443 · Peer API + Grants (&lt; 1s revoke)</text>

      <rect x="424" y="172" width="272" height="38" rx="8" fill="#101830" stroke="#10b981" strokeOpacity="0.45" />
      <text x="560" y="196" textAnchor="middle" fill="#a7f3d0" fontFamily="ui-monospace, monospace" fontSize="11.5">TCP 2049 · NFSv4.2 (afpeer0 bound)</text>

      <rect x="424" y="220" width="272" height="44" rx="8" fill="#101830" stroke="#d946ef" strokeOpacity="0.45" />
      <text x="560" y="240" textAnchor="middle" fill="#f5d0fe" fontFamily="ui-monospace, monospace" fontSize="11.5">1 WS / Job · Transcode Stream</text>
      <text x="560" y="256" textAnchor="middle" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="10">6-digit HTTPS pairing · 10m window</text>

      {/* Connector bars */}
      <line x1="358" y1="170" x2="400" y2="170" stroke="#22d3ee" strokeWidth="3" />
      <line x1="720" y1="170" x2="762" y2="170" stroke="#d946ef" strokeWidth="3" />

      {/* Right Server */}
      <rect x="762" y="34" width="330" height="272" rx="16" fill="#0d1426" stroke="#d946ef" strokeOpacity="0.55" strokeWidth="1.5" />
      <text x="784" y="64" fill="#f0abfc" fontFamily="ui-monospace, monospace" fontSize="11" fontWeight="700">SERVER B · PEER / WORKER</text>
      <text x="784" y="92" fill="#ffffff" fontFamily="system-ui, sans-serif" fontSize="18" fontWeight="700">Sovereign Node (Debian 13)</text>
      <text x="784" y="116" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">afpeer0: 10.231.x.2 · UDP 51821</text>

      <rect x="784" y="136" width="286" height="44" rx="9" fill="#121b33" stroke="#6366f1" strokeOpacity="0.4" />
      <text x="798" y="156" fill="#e0e7ff" fontFamily="ui-monospace, monospace" fontSize="11.5" fontWeight="700">Inbound Grants (Default: None)</text>
      <text x="798" y="172" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">Per-area Read / Write + instant revoke</text>

      <rect x="784" y="190" width="286" height="44" rx="9" fill="#121b33" stroke="#10b981" strokeOpacity="0.4" />
      <text x="798" y="210" fill="#d1fae5" fontFamily="ui-monospace, monospace" fontSize="11.5" fontWeight="700">NFSv4.2 Exports (ro,root_squash)</text>
      <text x="798" y="226" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">AF_ALLOWED_FS_ROOTS · /etc/nfs.conf.d/</text>

      <rect x="784" y="244" width="286" height="44" rx="9" fill="#121b33" stroke="#d946ef" strokeOpacity="0.4" />
      <text x="798" y="264" fill="#f5d0fe" fontFamily="ui-monospace, monospace" fontSize="11.5" fontWeight="700">af-transcode-worker.service</text>
      <text x="798" y="280" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">PrivateNetwork=yes · transcode.env</text>
    </svg>
  );
}

export function PeerClusteringSection({
  peerClusteringSvgSrc,
}: PeerClusteringSectionProps) {
  const [svgFailed, setSvgFailed] = useState(false);
  const [copiedDiag, setCopiedDiag] = useState(false);
  const showSvg = Boolean(peerClusteringSvgSrc) && !svgFailed;

  async function copyDiagnoseCmd() {
    try {
      await navigator.clipboard.writeText(peerClusteringContent.diagnosticsCommand);
      setCopiedDiag(true);
      window.setTimeout(() => setCopiedDiag(false), 2000);
    } catch {
      // Clipboard API unavailable in restricted contexts
    }
  }

  return (
    <section
      id="peer-clustering"
      aria-labelledby="peer-clustering-heading"
      className="scroll-mt-20 border-t border-white/[0.07] bg-gradient-to-b from-cyan-500/[0.03] via-transparent to-transparent py-20 sm:py-28"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/35 bg-cyan-500/12 px-3 py-1 font-mono text-xs font-semibold text-cyan-200">
              <Network className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{peerClusteringContent.eyebrow}</span>
            </div>
            <h2
              id="peer-clustering-heading"
              className="mt-4 text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-[2.6rem]"
            >
              {peerClusteringContent.title}
            </h2>
            <p className="mt-3 text-base leading-relaxed text-slate-300">
              {peerClusteringContent.subtitle}
            </p>
          </div>

          <a
            href={`${DOCS_BLOB_BASE}/docs/peer-clustering.md`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex shrink-0 items-center gap-1.5 self-start rounded-xl border border-cyan-400/35 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-100 transition-colors hover:bg-cyan-500/20 lg:self-auto"
          >
            <span>Peer Clustering operator guide</span>
            <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
          </a>
        </div>

        {/* Peer Clustering Topology Diagram */}
        <div className="mt-10 overflow-hidden rounded-2xl border border-white/[0.08] bg-[#07070c] shadow-[0_24px_64px_rgba(0,0,0,0.62)]">
          {showSvg && peerClusteringSvgSrc ? (
            <img
              src={peerClusteringSvgSrc}
              alt="AetherFlow Peer Clustering architecture showing afpeer0 WireGuard mesh, six-digit pairing, 8-area grants, NFSv4.2 media federation, and distributed Jellyfin 12.4 transcoding"
              width={1600}
              height={800}
              onError={() => setSvgFailed(true)}
              className="block h-auto w-full"
            />
          ) : (
            <div className="p-3 sm:p-5">
              <FallbackPeerTopologySvg />
            </div>
          )}
        </div>

        {/* 4 Core Pillars */}
        <div className="mt-8 grid grid-cols-1 gap-5 md:grid-cols-2">
          {peerClusteringContent.pillars.map((pillar) => (
            <article
              key={pillar.title}
              className="obs-glass flex flex-col justify-between rounded-2xl p-6"
            >
              <div>
                <span
                  className={`inline-flex rounded-lg border px-2.5 py-1 font-mono text-[11px] font-semibold ${TONE_ACCENT[pillar.tone]}`}
                >
                  {pillar.meta}
                </span>
                <h3 className="mt-3.5 text-lg font-bold text-white">
                  {pillar.title}
                </h3>
                <p className="mt-2.5 text-sm leading-relaxed text-slate-300">
                  {pillar.detail}
                </p>
              </div>
            </article>
          ))}
        </div>

        {/* 8 Grant Areas + CLI & Scope Strip */}
        <div className="mt-8 grid grid-cols-1 gap-5 lg:grid-cols-12">
          <div className="obs-glass rounded-2xl p-6 lg:col-span-7">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-indigo-300" aria-hidden="true" />
                <h3 className="text-base font-bold text-white">
                  8 Scoped Grant Areas (Zero Access by Default)
                </h3>
              </div>
              <span className="inline-flex items-center gap-1 rounded-full border border-emerald-400/30 bg-emerald-500/10 px-2.5 py-0.5 font-mono text-[11px] text-emerald-300">
                <Lock className="h-3 w-3" aria-hidden="true" />
                None · Read · Read &amp; Write
              </span>
            </div>
            <div className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              {peerClusteringContent.grantAreas.map((g) => (
                <div
                  key={g.area}
                  className="rounded-xl border border-white/[0.07] bg-white/[0.025] px-3.5 py-2.5"
                >
                  <div className="font-mono text-xs font-bold text-cyan-300">
                    {g.area}
                  </div>
                  <div className="mt-0.5 text-xs leading-snug text-slate-400">
                    {g.desc}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-5 lg:col-span-5">
            <div className="obs-glass rounded-2xl p-6">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <Terminal className="h-4 w-4 text-cyan-300" aria-hidden="true" />
                <span>Read-Only Link Diagnostics CLI</span>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-slate-400">
                Inspect WireGuard peer handshakes, tunnel RTT, mount parity, and grant state from the shell:
              </p>
              <div className="obs-code-block mt-3 flex items-center justify-between gap-3 rounded-xl px-4 py-3">
                <code className="overflow-x-auto text-xs text-cyan-200 sm:text-sm">
                  {peerClusteringContent.diagnosticsCommand}
                </code>
                <button
                  type="button"
                  onClick={copyDiagnoseCmd}
                  aria-label="Copy af cluster diagnose command"
                  className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-white/10 bg-white/[0.06] px-2.5 py-1.5 font-mono text-[11px] text-slate-200 transition-colors hover:border-cyan-400/40 hover:text-white"
                >
                  {copiedDiag ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            <div className="rounded-2xl border border-amber-400/25 bg-amber-500/[0.06] p-6">
              <div className="flex items-start gap-3">
                <AlertTriangle
                  className="mt-0.5 h-5 w-5 shrink-0 text-amber-300"
                  aria-hidden="true"
                />
                <div>
                  <h3 className="text-sm font-bold text-amber-100">
                    Prerequisites &amp; Scope Boundaries
                  </h3>
                  <p className="mt-1.5 text-xs leading-relaxed text-amber-100/80">
                    {peerClusteringContent.scopeNote}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
