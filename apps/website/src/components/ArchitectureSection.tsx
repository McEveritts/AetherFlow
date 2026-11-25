'use client';

import { useState } from 'react';
import { ArrowUpRight, Layers, Shield, Terminal } from 'lucide-react';
import {
  backendCrates,
  frontendCrates,
  DOCS_BLOB_BASE,
  type AccentTone,
} from '@/content/home';

interface ArchitectureSectionProps {
  architectureSvgSrc: string | null;
}

const TONE_PILL: Record<AccentTone, string> = {
  indigo: 'border-indigo-400/30 bg-indigo-500/15 text-indigo-200',
  violet: 'border-violet-400/30 bg-violet-500/15 text-violet-200',
  cyan: 'border-cyan-400/30 bg-cyan-500/15 text-cyan-200',
  fuchsia: 'border-fuchsia-400/30 bg-fuchsia-500/15 text-fuchsia-200',
  emerald: 'border-emerald-400/30 bg-emerald-500/15 text-emerald-200',
  amber: 'border-amber-400/30 bg-amber-500/15 text-amber-200',
};

function FallbackArchitectureSvg() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1160 440"
      role="img"
      aria-label="AetherFlow v4.0.0 system architecture diagram showing Leptos WASM browser, Apache2 TLS ingress, unprivileged 12-crate Rust aetherflow-api, runner.sock privilege boundary, root aetherflow-runner, and bare-metal systemd workloads"
      className="h-auto w-full"
    >
      <defs>
        <linearGradient id="archBg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#070a12" />
          <stop offset="100%" stopColor="#0d1222" />
        </linearGradient>
        <linearGradient id="archEdge" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#22d3ee" />
          <stop offset="50%" stopColor="#6366f1" />
          <stop offset="100%" stopColor="#d946ef" />
        </linearGradient>
        <marker
          id="archArrow"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#818cf8" />
        </marker>
      </defs>

      <rect width="1160" height="440" rx="16" fill="url(#archBg)" />

      {/* Operator Browser */}
      <rect x="28" y="42" width="210" height="120" rx="14" fill="#0f1528" stroke="#8b5cf6" strokeOpacity="0.55" strokeWidth="1.5" />
      <text x="48" y="72" fill="#c4b5fd" fontFamily="ui-monospace, monospace" fontSize="11" fontWeight="700">FRONTEND-RS (4 CRATES)</text>
      <text x="48" y="98" fill="#ffffff" fontFamily="system-ui, sans-serif" fontSize="16" fontWeight="700">Leptos WASM SPA</text>
      <text x="48" y="121" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="12">16 tabs · WASM workers</text>
      <text x="48" y="140" fill="#67e8f9" fontFamily="ui-monospace, monospace" fontSize="11">served from web/dist</text>

      {/* Apache2 Ingress */}
      <rect x="28" y="246" width="210" height="130" rx="14" fill="#0f1528" stroke="#22d3ee" strokeOpacity="0.45" strokeWidth="1.5" />
      <text x="48" y="276" fill="#67e8f9" fontFamily="ui-monospace, monospace" fontSize="11" fontWeight="700">TLS &amp; SUBDOMAIN INGRESS</text>
      <text x="48" y="302" fill="#ffffff" fontFamily="system-ui, sans-serif" fontSize="16" fontWeight="700">Apache2 Gateway</text>
      <text x="48" y="325" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="12">&lt;app&gt;.&lt;baseDomain&gt;</text>
      <text x="48" y="346" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="12">*.aether.local + Certbot SANs</text>

      {/* Arrow Browser -> Apache */}
      <line x1="133" y1="162" x2="133" y2="238" stroke="#818cf8" strokeWidth="2" markerEnd="url(#archArrow)" />
      <text x="144" y="206" fill="#a5b4fc" fontFamily="ui-monospace, monospace" fontSize="11">HTTPS / WSS</text>

      {/* Control Plane Box */}
      <rect x="292" y="36" width="414" height="368" rx="16" fill="#0b1020" stroke="#6366f1" strokeOpacity="0.6" strokeWidth="1.5" />
      <text x="314" y="66" fill="#a5b4fc" fontFamily="ui-monospace, monospace" fontSize="11" fontWeight="700">UNPRIVILEGED CONTROL PLANE · USER=AETHERFLOW</text>
      <text x="314" y="92" fill="#ffffff" fontFamily="system-ui, sans-serif" fontSize="18" fontWeight="700">aetherflow-api (12-Crate backend-rs)</text>
      <text x="314" y="114" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">ProtectSystem=strict · NoNewPrivileges=yes · 127.0.0.1:8080</text>

      {/* Inner subsystem cards */}
      <rect x="314" y="132" width="180" height="72" rx="10" fill="#121a30" stroke="#4f46e5" strokeOpacity="0.45" />
      <text x="328" y="156" fill="#e0e7ff" fontFamily="ui-monospace, monospace" fontSize="12" fontWeight="700">af-db (SQLite WAL)</text>
      <text x="328" y="176" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">1W/8R pools · AES-256-GCM</text>
      <text x="328" y="192" fill="#34d399" fontFamily="ui-monospace, monospace" fontSize="10">No Redis dependency</text>

      <rect x="508" y="132" width="176" height="72" rx="10" fill="#121a30" stroke="#22d3ee" strokeOpacity="0.4" />
      <text x="522" y="156" fill="#cffafe" fontFamily="ui-monospace, monospace" fontSize="12" fontWeight="700">af-files + af-hardware</text>
      <text x="522" y="176" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">openat2 McBrowser (0700)</text>
      <text x="522" y="192" fill="#67e8f9" fontFamily="ui-monospace, monospace" fontSize="10">Zero-fork /proc + NVML</text>

      <rect x="314" y="218" width="180" height="72" rx="10" fill="#121a30" stroke="#d946ef" strokeOpacity="0.4" />
      <text x="328" y="242" fill="#f5d0fe" fontFamily="ui-monospace, monospace" fontSize="12" fontWeight="700">af-services + FlowAI</text>
      <text x="328" y="262" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">Catalog · Streaming · af-heal</text>
      <text x="328" y="278" fill="#f0abfc" fontFamily="ui-monospace, monospace" fontSize="10">Approval Inbox gated</text>

      <rect x="508" y="218" width="176" height="72" rx="10" fill="#121a30" stroke="#10b981" strokeOpacity="0.4" />
      <text x="522" y="242" fill="#d1fae5" fontFamily="ui-monospace, monospace" fontSize="12" fontWeight="700">Peer API + af-transcode</text>
      <text x="522" y="262" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="11">afpeer0 TCP 9443 listener</text>
      <text x="522" y="278" fill="#34d399" fontFamily="ui-monospace, monospace" fontSize="10">8-area scoped grants</text>

      <rect x="314" y="304" width="370" height="80" rx="10" fill="#10172b" stroke="#f59e0b" strokeOpacity="0.35" />
      <text x="328" y="329" fill="#fde68a" fontFamily="ui-monospace, monospace" fontSize="12" fontWeight="700">Sibling Binaries in /opt/AetherFlow/current</text>
      <text x="328" y="350" fill="#cbd5e1" fontFamily="ui-monospace, monospace" fontSize="11">bin/af (CLI) · bin/speedtest-backend (af-librespeed)</text>
      <text x="328" y="369" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">bin/af-transcode (Jellyfin shim &amp; worker) · web/dist</text>

      {/* Arrow Apache -> API */}
      <line x1="238" y1="310" x2="284" y2="310" stroke="#818cf8" strokeWidth="2" markerEnd="url(#archArrow)" />

      {/* Privilege Boundary Line + Arrow API -> Runner */}
      <line x1="706" y1="210" x2="778" y2="210" stroke="url(#archEdge)" strokeWidth="2.5" markerEnd="url(#archArrow)" />
      <rect x="708" y="160" width="76" height="36" rx="6" fill="#090d18" stroke="#10b981" strokeOpacity="0.45" />
      <text x="746" y="176" textAnchor="middle" fill="#34d399" fontFamily="ui-monospace, monospace" fontSize="9.5" fontWeight="700">runner.sock</text>
      <text x="746" y="190" textAnchor="middle" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="8.5">SO_PEERCRED</text>

      {/* Privileged Runner & Host */}
      <rect x="790" y="36" width="342" height="162" rx="14" fill="#0d1424" stroke="#10b981" strokeOpacity="0.55" strokeWidth="1.5" />
      <text x="812" y="64" fill="#34d399" fontFamily="ui-monospace, monospace" fontSize="11" fontWeight="700">ZERO-SUDO PRIVILEGE BOUNDARY</text>
      <text x="812" y="90" fill="#ffffff" fontFamily="system-ui, sans-serif" fontSize="16" fontWeight="700">aetherflow-runner.service</text>
      <text x="812" y="114" fill="#cbd5e1" fontFamily="system-ui, sans-serif" fontSize="12">Strict allowlisted IPC verbs:</text>
      <text x="812" y="136" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">/v1/systemctl · /v1/package · /v1/quota</text>
      <text x="812" y="156" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">/v1/peer-&#123;network,storage,transcode&#125;</text>
      <text x="812" y="176" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">/v1/self-update · /v1/plugins (DynamicUser)</text>

      {/* Arrow Runner -> Bare Metal */}
      <line x1="961" y1="198" x2="961" y2="236" stroke="#34d399" strokeWidth="2" markerEnd="url(#archArrow)" />

      {/* Bare Metal Host Box */}
      <rect x="790" y="244" width="342" height="160" rx="14" fill="#0d1424" stroke="#f59e0b" strokeOpacity="0.45" strokeWidth="1.5" />
      <text x="812" y="272" fill="#fbbf24" fontFamily="ui-monospace, monospace" fontSize="11" fontWeight="700">BARE-METAL LINUX HOST (SYSTEMD)</text>
      <text x="812" y="298" fill="#ffffff" fontFamily="system-ui, sans-serif" fontSize="16" fontWeight="700">77 Native Marketplace Apps</text>
      <text x="812" y="322" fill="#94a3b8" fontFamily="system-ui, sans-serif" fontSize="12">Plex · Jellyfin · *Arr · qBittorrent · WireGuard</text>
      <text x="812" y="344" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">af-release transient self-update units</text>
      <text x="812" y="366" fill="#94a3b8" fontFamily="ui-monospace, monospace" fontSize="11">wg-quick@afpeer0 + NFSv4.2 .mount units</text>
      <text x="812" y="388" fill="#34d399" fontFamily="ui-monospace, monospace" fontSize="10.5">Debian 12/13 · Ubuntu 22.04/24.04 LTS</text>
    </svg>
  );
}

export function ArchitectureSection({
  architectureSvgSrc,
}: ArchitectureSectionProps) {
  const [svgFailed, setSvgFailed] = useState(false);
  const [workspaceTab, setWorkspaceTab] = useState<'backend' | 'frontend'>('backend');
  const showSvg = Boolean(architectureSvgSrc) && !svgFailed;

  const activeCrates = workspaceTab === 'backend' ? backendCrates : frontendCrates;

  return (
    <section
      id="architecture"
      aria-labelledby="architecture-heading"
      className="scroll-mt-20 border-t border-white/[0.07] py-20 sm:py-28"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div className="max-w-3xl">
            <p className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-indigo-300">
              System Architecture
            </p>
            <h2
              id="architecture-heading"
              className="mt-2 text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-[2.6rem]"
            >
              12 backend crates, 4 WASM crates, one privilege boundary
            </h2>
            <p className="mt-3 text-base leading-relaxed text-slate-300">
              Unprivileged <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-indigo-200">aetherflow-api</code> serves the Leptos WASM dashboard from external <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-indigo-200">web/dist</code> assets and delegates root operations over <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-emerald-300">/run/aetherflow/runner.sock</code> to <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-emerald-300">aetherflow-runner.service</code>.
            </p>
          </div>

          <a
            href={`${DOCS_BLOB_BASE}/docs/architecture.md`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex shrink-0 items-center gap-1.5 self-start rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-indigo-400/45 hover:text-white lg:self-auto"
          >
            <span>Architecture reference</span>
            <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
          </a>
        </div>

        {/* Diagram Frame */}
        <div className="mt-10 overflow-hidden rounded-2xl border border-white/[0.08] bg-[#07070c] shadow-[0_24px_64px_rgba(0,0,0,0.62)]">
          {showSvg && architectureSvgSrc ? (
            <img
              src={architectureSvgSrc}
              alt="AetherFlow v4.0.0 System Architecture diagram showing the 12-crate Rust control plane, 4-crate Leptos WASM frontend, Apache2 ingress, and zero-sudo runner.sock boundary"
              width={1600}
              height={900}
              onError={() => setSvgFailed(true)}
              className="block h-auto w-full"
            />
          ) : (
            <div className="p-3 sm:p-5">
              <FallbackArchitectureSvg />
            </div>
          )}
        </div>

        {/* Workspace Crate Explorer */}
        <div className="mt-10">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div
              role="tablist"
              aria-label="Rust workspaces"
              className="inline-flex rounded-xl border border-white/10 bg-white/[0.03] p-1"
            >
              <button
                type="button"
                role="tab"
                aria-selected={workspaceTab === 'backend'}
                onClick={() => setWorkspaceTab('backend')}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors ${
                  workspaceTab === 'backend'
                    ? 'bg-indigo-500/25 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal className="h-4 w-4 text-indigo-300" aria-hidden="true" />
                <span>backend-rs (12 Crates)</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={workspaceTab === 'frontend'}
                onClick={() => setWorkspaceTab('frontend')}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors ${
                  workspaceTab === 'frontend'
                    ? 'bg-violet-500/25 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="h-4 w-4 text-violet-300" aria-hidden="true" />
                <span>frontend-rs (4 WASM Crates)</span>
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-3 font-mono text-xs text-slate-400">
              <span className="inline-flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                Immutable slots: /opt/AetherFlow/releases/&lt;ts&gt; → current
              </span>
            </div>
          </div>

          <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {activeCrates.map((crate) => (
              <div
                key={crate.name}
                className="obs-glass flex flex-col justify-between rounded-xl p-4 transition-colors hover:border-indigo-400/35"
              >
                <div>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-mono text-sm font-bold text-white">
                      {crate.name}
                    </h3>
                    {crate.binary && (
                      <span
                        className={`rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium ${TONE_PILL[crate.tone]}`}
                      >
                        {crate.binary}
                      </span>
                    )}
                  </div>
                  <p className="mt-2.5 text-xs leading-relaxed text-slate-300 sm:text-[13px]">
                    {crate.role}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
