export const REPO_URL = 'https://github.com/McEveritts/AetherFlow';
export const RELEASES_URL = `${REPO_URL}/releases`;
export const DOCS_BLOB_BASE = `${REPO_URL}/blob/master`;

export type AccentTone =
  | 'indigo'
  | 'violet'
  | 'cyan'
  | 'fuchsia'
  | 'emerald'
  | 'amber';

export const navLinks = [
  { label: 'Features', href: '#features' },
  { label: 'Dashboard', href: '#gallery' },
  { label: 'Architecture', href: '#architecture' },
  { label: 'Peer Clustering', href: '#peer-clustering' },
  { label: 'Catalog', href: '#catalog' },
  { label: 'Install', href: '#install' },
  { label: 'v4.0.2 Notes', href: '#whats-new' },
] as const;

export const heroContent = {
  versionPill: 'v4.0.2 • Pure Rust Control Plane & Flat WASM UI',
  headlineLead: 'Bare-metal Linux infrastructure,',
  headlineAccent: 'orchestrated in pure Rust.',
  subheadline:
    'AetherFlow v4.0.2 pairs a 12-crate Rust control plane (Axum + Tokio) with a 4-crate Leptos WebAssembly dashboard built on the Unified Flat Surface & Control System. Provision 77 native systemd applications, pair independent servers over an afpeer0 WireGuard mesh, manage scoped tenant storage in McBrowser, and gate FlowAI operations behind explicit human approval.',
  primaryCta: {
    label: 'Explore on GitHub',
    href: REPO_URL,
  },
  secondaryCta: {
    label: 'Quickstart Guide',
    href: `${DOCS_BLOB_BASE}/docs/quickstart.md`,
  },
  releasesCta: {
    label: 'v4.0.2 Releases',
    href: RELEASES_URL,
  },
  trustPills: [
    'Debian 12/13 · Ubuntu 22.04/24.04',
    'Zero Go · Zero Docker · Zero Redis',
    'Sigstore & SLSA v1 Provenance',
    'GPL-3.0 Open Source',
  ],
};

export interface StatItem {
  value: string;
  label: string;
  detail: string;
  tone: AccentTone;
}

export const statsByTheNumbers: StatItem[] = [
  {
    value: '12',
    label: 'Rust Backend Crates',
    detail: 'backend-rs workspace compiling API, runner, CLI, LibreSpeed, and af-transcode',
    tone: 'indigo',
  },
  {
    value: '4',
    label: 'Leptos WASM Crates',
    detail: 'frontend-rs workspace shipping 16 operational tabs as static web/dist assets',
    tone: 'violet',
  },
  {
    value: '77',
    label: 'Native Bare-Metal Apps',
    detail: 'Managed across 9 Marketplace categories directly under systemd',
    tone: 'cyan',
  },
  {
    value: '0',
    label: 'Go, Docker or Redis Daemons',
    detail: 'Zero-Go cutover complete; bundled SQLite WAL handles sessions & state',
    tone: 'emerald',
  },
  {
    value: '374',
    label: 'Commits Since v3.2.7',
    detail: 'End-to-end Rust control plane, WASM dashboard, and Peer Clustering rewrite',
    tone: 'fuchsia',
  },
  {
    value: '8',
    label: 'Scoped Peer Grant Areas',
    detail: 'Zero-access default over afpeer0 WireGuard with < 1s stream revocation',
    tone: 'amber',
  },
];

export interface FeatureItem {
  id: string;
  title: string;
  tag: string;
  summary: string;
  specs: string[];
  tone: AccentTone;
  docHref: string;
}

export const features: FeatureItem[] = [
  {
    id: 'rust-control-plane',
    title: '12-Crate Rust Control Plane',
    tag: 'backend-rs · Axum + Tokio',
    summary:
      'Compiled native binaries replace shell panels and Go daemons. Bundled SQLite WAL runs split 1-writer / 8-reader pools, zero-fork /proc and NVML GPU FFI collect hardware telemetry, and af-librespeed ships a native Rust speedtest-backend.',
    specs: ['aetherflow-api + af CLI', 'SQLite WAL (no Redis)', 'NVML & DRM sysfs FFI'],
    tone: 'indigo',
    docHref: `${DOCS_BLOB_BASE}/docs/architecture.md`,
  },
  {
    id: 'leptos-wasm',
    title: 'Leptos Rust WASM Dashboard',
    tag: 'frontend-rs · 16 Tabs',
    summary:
      'Built from 4 Rust WebAssembly crates via Trunk and served directly from external web/dist assets by aetherflow-api. Features Frame-0 WebSocket telemetry snapshots, background WASM workers, and the Unified Flat Surface & Control System—zero Node.js runtime required.',
    specs: ['External web/dist assets', 'Dedicated WASM workers', '6 UTC telemetry windows'],
    tone: 'violet',
    docHref: `${DOCS_BLOB_BASE}/frontend-rs/README.md`,
  },
  {
    id: 'marketplace',
    title: '77-App Bare-Metal Marketplace',
    tag: 'config/packages.json · 9 Categories',
    summary:
      'Provision media servers, the *Arr stack, downloaders, VPNs, monitoring, and remote desktops directly on Linux. Operations serialize behind .af-package-executor.flock with locked Bash installers, 9 opt-in declarative Rust recipes, and live SSE/WS install logs.',
    specs: ['Native systemd units', '9 opt-in Rust recipes', 'Auto *Arr API discovery'],
    tone: 'cyan',
    docHref: `${DOCS_BLOB_BASE}/docs/marketplace.md`,
  },
  {
    id: 'peer-clustering',
    title: 'Peer Clustering & Offload',
    tag: 'afpeer0 · NFSv4.2 · af-transcode',
    summary:
      'Pair independent Debian 13 servers over a dedicated WireGuard mesh with six-digit verification, zero-access-by-default 8-area grants, health-gated NFSv4.2 media folder sharing, and distributed Jellyfin 12.4 transcode offload.',
    specs: ['6-digit HTTPS pairing', '< 1s grant revocation', 'af cluster diagnose <link>'],
    tone: 'cyan',
    docHref: `${DOCS_BLOB_BASE}/docs/peer-clustering.md`,
  },
  {
    id: 'mcbrowser',
    title: 'Native McBrowser',
    tag: 'af-files · Linux openat2',
    summary:
      'Built-in per-user file workspace without extra containers or separate logins. Enforces 0700 per-user roots via openat2 confinement, 64 GiB resumable TUS uploads, ETag-guarded UTF-8 editing (up to 10 MiB, 45 syntax modes), 9-format archives, and POSIX setquota limits.',
    specs: ['64 GiB TUS uploads', '45-mode UTF-8 editor', '9-format archive tools'],
    tone: 'indigo',
    docHref: `${DOCS_BLOB_BASE}/docs/mcbrowser.md`,
  },
  {
    id: 'streaming',
    title: 'Canonical Streaming Intelligence',
    tag: 'Jellyfin · Plex · Emby (Staged)',
    summary:
      'Unified real-time session telemetry and snapshot-consistent playback history archive with server-identity verification, distribution charts, native Plex/Tautulli JSON & CSV import, portable archive exports, and human-gated reconciliation.',
    specs: ['Live session control', 'Plex & Tautulli import', 'CSV/JSON portability'],
    tone: 'emerald',
    docHref: `${DOCS_BLOB_BASE}/docs/streaming-history-contract.md`,
  },
  {
    id: 'flowai',
    title: 'Human-Gated FlowAI',
    tag: '5 LLM Providers · Approval Inbox',
    summary:
      'Diagnostics grounded in live hardware telemetry and audit logs across Google Gemini, Anthropic Claude, OpenAI, Ollama, and LM Studio. API keys are AES-256-GCM encrypted at rest, and proposed service mutations queue in pending_actions for explicit admin sign-off.',
    specs: ['AES-256-GCM enc:v1: keys', 'Untrusted AI boundary', 'Approval Inbox & audit log'],
    tone: 'fuchsia',
    docHref: `${DOCS_BLOB_BASE}/docs/flowai.md`,
  },
  {
    id: 'networking',
    title: 'WireGuard, Tailscale & Ingress',
    tag: 'wg0 · Tailnet · <app>.<baseDomain>',
    summary:
      'Provision one-time WireGuard client keypairs with QR codes, manage Tailscale routes and exit nodes, expose opt-in HTTP apps at <app>.<baseDomain> through Apache2 with automated af-certbot-sync SANs, and sync .aether.local split-horizon LAN DNS.',
    specs: ['wg0 peer & QR provisioning', 'Tailscale mesh & routes', 'Automated Certbot SANs'],
    tone: 'violet',
    docHref: `${DOCS_BLOB_BASE}/docs/network-vpn.md`,
  },
  {
    id: 'security',
    title: 'Zero-Sudo Security & Supply Chain',
    tag: 'runner.sock · Sigstore · DynamicUser',
    summary:
      'Unprivileged aetherflow-api (ProtectSystem=strict, NoNewPrivileges=yes) delegates privileged operations over /run/aetherflow/runner.sock with SO_PEERCRED and /proc/<pid>/exe checks. Ships TOTP 2FA, OIDC/PKCE, DynamicUser=yes plugins, and Sigstore/SLSA v1 verification.',
    specs: ['Zero-sudo runner socket', 'TOTP 2FA & OIDC PKCE', 'Rekor v1/v2 & SLSA v1'],
    tone: 'emerald',
    docHref: `${DOCS_BLOB_BASE}/SECURITY.md`,
  },
  {
    id: 'self-update',
    title: 'Atomic Self-Update & Rollback',
    tag: 'af-release · Transient systemd',
    summary:
      'Updates execute inside isolated transient aetherflow-self-update-<cmd>-<channel>-<8hex>.service units that verify SHA256SUMS and Sigstore provenance, take WAL-safe VACUUM INTO backups, verify /proc/<pid>/exe across both services, and auto-rollback on failure.',
    specs: ['Immutable /releases slots', 'WAL-safe VACUUM INTO', 'Auto-rollback & receipts'],
    tone: 'amber',
    docHref: `${DOCS_BLOB_BASE}/docs/self-update.md`,
  },
];

export type GalleryGroupId =
  | 'operations'
  | 'media'
  | 'infrastructure'
  | 'governance';

export interface GalleryGroup {
  id: GalleryGroupId;
  label: string;
}

export const galleryGroups: GalleryGroup[] = [
  { id: 'operations', label: 'Operations & Core' },
  { id: 'media', label: 'Media & Storage' },
  { id: 'infrastructure', label: 'Infrastructure & AI' },
  { id: 'governance', label: 'Security & Governance' },
];

export type GalleryScreenId =
  | 'overview'
  | 'inbox'
  | 'services'
  | 'marketplace'
  | 'mcbrowser'
  | 'fileshare'
  | 'streaming'
  | 'mediaflow'
  | 'flowai'
  | 'network'
  | 'cluster'
  | 'users'
  | 'audit'
  | 'settings'
  | 'notifications'
  | 'quotas'
  | 'security';

export interface GalleryView {
  id: GalleryScreenId;
  group: GalleryGroupId;
  label: string;
  route: string;
  tagline: string;
  description: string;
  highlights: string[];
  tone: AccentTone;
}

export const galleryViews: GalleryView[] = [
  {
    id: 'overview',
    group: 'operations',
    label: 'Overview',
    route: '/?tab=overview',
    tagline: 'Frame-0 WebSocket Telemetry & Hardware Topology',
    description:
      'Immediate live snapshots of CPU, memory, disk I/O, network throughput, and NVML GPU metrics across six UTC history windows with server-side aggregation and gap detection.',
    highlights: ['Zero-fork /proc + NVML FFI', '6 UTC telemetry windows', 'Live service health topology'],
    tone: 'indigo',
  },
  {
    id: 'inbox',
    group: 'operations',
    label: 'Approval Inbox',
    route: '/?tab=inbox',
    tagline: 'Human-Gated Remediation & Action Sign-Off',
    description:
      'Every FlowAI service mutation and af-heal watchdog remediation queues inside pending_actions until an administrator explicitly approves or declines execution with durable receipts.',
    highlights: ['pending_actions SQLite gate', 'FlowAI & af-heal queue', 'Audited approval receipts'],
    tone: 'amber',
  },
  {
    id: 'services',
    group: 'operations',
    label: 'Services',
    route: '/?tab=services',
    tagline: 'Direct systemd Lifecycle, Journald Logs & af-heal',
    description:
      'Inspect and control managed Linux services over runner.sock allowlists, tail O_NOFOLLOW journald streams, verify systemd sandbox drop-ins, and review restart receipts.',
    highlights: ['Allowlisted runner.sock IPC', 'Live O_NOFOLLOW log tail', 'af-heal watchdog status'],
    tone: 'amber',
  },
  {
    id: 'marketplace',
    group: 'operations',
    label: 'Marketplace',
    route: '/?tab=marketplace',
    tagline: '77 Native Bare-Metal Apps Across 9 Categories',
    description:
      'Install, update, and uninstall bare-metal Linux services directly on systemd with live SSE/WS install streaming, certified version receipts, and one-click subdomain ingress links.',
    highlights: ['77 apps in 9 categories', 'Certified update receipts', 'Auto *Arr API key discovery'],
    tone: 'violet',
  },
  {
    id: 'notifications',
    group: 'operations',
    label: 'Notifications',
    route: '/?tab=notifications',
    tagline: 'Encrypted Alert Channels, Rules & Peer Offers',
    description:
      'Configure webhook and alert channels encrypted at rest with AES-256-GCM (enc:v1:), inspect system health alerts, and review incoming peer access offer notifications.',
    highlights: ['AES-256-GCM channel secrets', 'DNS-pinned SSRF webhooks', 'Peer access offer notices'],
    tone: 'indigo',
  },
  {
    id: 'streaming',
    group: 'media',
    label: 'Streaming',
    route: '/?tab=streaming',
    tagline: 'Canonical Playback Archive & Live Sessions',
    description:
      'Monitor active Jellyfin, Plex, and Emby (staged) streams alongside snapshot-consistent playback history, distribution charts, native Plex/Tautulli imports, and portable CSV/JSON archives.',
    highlights: ['Jellyfin · Plex · Emby', 'Native Tautulli import', 'Reconciliation gates'],
    tone: 'emerald',
  },
  {
    id: 'mediaflow',
    group: 'media',
    label: 'MediaFlow',
    route: '/?tab=mediaflow',
    tagline: 'Library Scan & Operator-Approved Transcode Queue',
    description:
      'Scan media libraries for codec optimization candidates and review, approve, or decline background FFmpeg transcoding jobs managed by the af-services MediaFlow worker.',
    highlights: ['Automated codec scans', 'Approve / decline workflow', 'Background queue worker'],
    tone: 'violet',
  },
  {
    id: 'mcbrowser',
    group: 'media',
    label: 'McBrowser',
    route: '/?tab=mcbrowser',
    tagline: 'openat2-Confined Tenant File Manager & Code Editor',
    description:
      'Browse 0700 per-user storage without separate web apps. Supports 64 GiB resumable TUS uploads, ETag-guarded UTF-8 editing (up to 10 MiB, 45 syntax modes), 9-format archives, and gallery previews.',
    highlights: ['Linux openat2 sandbox', '64 GiB resumable TUS', '45-mode UTF-8 code editor'],
    tone: 'indigo',
  },
  {
    id: 'fileshare',
    group: 'media',
    label: 'File Share',
    route: '/?tab=fileshare',
    tagline: 'Managed Uploads & Password-Protected Public Links',
    description:
      'Upload and share files via chunked streaming with optional password protection, expiration controls, download permission enforcement, and bounded preview streaming.',
    highlights: ['Chunked upload streaming', 'Password-protected shares', 'Download permission gates'],
    tone: 'cyan',
  },
  {
    id: 'cluster',
    group: 'infrastructure',
    label: 'Cluster',
    route: '/?tab=cluster',
    tagline: 'Encrypted Peer Mesh, Scoped Grants & Transcode Offload',
    description:
      'Pair independent Debian 13 hosts over afpeer0 WireGuard with six-digit verification, assign granular 8-area inbound/outbound grants, mount NFSv4.2 media folders, and dispatch Jellyfin 12.4 transcodes.',
    highlights: ['Zero-access default grants', 'Health-gated NFSv4.2 mounts', 'Jellyfin 12.4 af-transcode'],
    tone: 'cyan',
  },
  {
    id: 'network',
    group: 'infrastructure',
    label: 'Network',
    route: '/?tab=network',
    tagline: 'WireGuard, Tailscale & Automated Subdomain Ingress',
    description:
      'Generate WireGuard wg0 peer configs and QR codes, configure Tailscale subnet routers and exit nodes, toggle per-app External Access HTTPS ingress, and inspect host NIC inventory.',
    highlights: ['wg0 peer QR codes', 'Tailscale mesh controls', 'Opt-in <app>.<baseDomain>'],
    tone: 'cyan',
  },
  {
    id: 'flowai',
    group: 'infrastructure',
    label: 'FlowAI',
    route: '/?tab=ai',
    tagline: 'Multi-Provider Diagnostics Gated by Approval Inbox',
    description:
      'Query live telemetry and audit logs via Gemini, Claude, OpenAI, Ollama, or LM Studio. Proposed systemd stop/restart remediations never run automatically—every mutation requires administrator approval.',
    highlights: ['5 native LLM providers', 'AES-256-GCM stored keys', 'Pending Actions Approval Inbox'],
    tone: 'fuchsia',
  },
  {
    id: 'security',
    group: 'governance',
    label: 'Security & 2FA',
    route: '/?tab=settings · Security & 2FA',
    tagline: 'TOTP 2FA, Recovery Codes & Active Session Families',
    description:
      'Enroll TOTP authenticators with bcrypt-hashed recovery codes, monitor personal storage quota consumption, and inspect or immediately revoke SQLite-backed active session families.',
    highlights: ['TOTP 2FA + recovery codes', 'Instant session revocation', 'No Redis session store'],
    tone: 'emerald',
  },
  {
    id: 'users',
    group: 'governance',
    label: 'Users',
    route: '/?tab=users',
    tagline: 'Multi-Tenant Accounts, Roles & Streaming Links',
    description:
      'Create and manage administrator and tenant accounts, enforce role boundaries across all 16 dashboard tabs, and map local accounts to Jellyfin, Plex, or Emby streaming identities.',
    highlights: ['Role-scoped tab access', 'Streaming identity links', 'Per-user McBrowser roots'],
    tone: 'indigo',
  },
  {
    id: 'quotas',
    group: 'governance',
    label: 'Quotas',
    route: '/?tab=quotas',
    tagline: 'Linux POSIX Disk Quotas & Tenant Storage Governance',
    description:
      'Set and monitor per-user storage limits backed by SQLite usage telemetry and AetherFlow’s setdisk runner wrapper invoking native Linux setquota.',
    highlights: ['POSIX setquota via runner', 'Live usage telemetry', 'McBrowser quota enforcement'],
    tone: 'amber',
  },
  {
    id: 'audit',
    group: 'governance',
    label: 'Audit Trail',
    route: '/?tab=audit',
    tagline: 'Persistent SQLite Administrator Audit Ledger',
    description:
      'Inspect chronological admin_audit_log records covering authentication events, Marketplace package installs, McBrowser mutations, peer grant updates, and Approval Inbox decisions.',
    highlights: ['admin_audit_log in SQLite', 'Filterable action ledger', 'Redacted diagnostic safety'],
    tone: 'emerald',
  },
  {
    id: 'settings',
    group: 'governance',
    label: 'Settings',
    route: '/?tab=settings',
    tagline: 'Backups, OIDC/PKCE Clients, Localization & Self-Update',
    description:
      'Manage system localization, FlowAI providers, WAL-safe VACUUM INTO backups & staged restores, OIDC/PKCE & device-flow clients, and isolated atomic self-update channels.',
    highlights: ['WAL-safe VACUUM INTO backups', 'OIDC PKCE & device flow', 'Sigstore atomic self-update'],
    tone: 'violet',
  },
];

export interface CrateEntry {
  name: string;
  binary?: string;
  role: string;
  tone: AccentTone;
}

export const backendCrates: CrateEntry[] = [
  {
    name: 'af-api',
    binary: 'aetherflow-api',
    role: 'Axum HTTP/WS control plane, external web/dist asset server, JWT/TOTP/OIDC/CSRF auth, McBrowser routes, plugin proxy, FlowAI, streaming, and peer API listener.',
    tone: 'indigo',
  },
  {
    name: 'af-runner',
    binary: 'aetherflow-api runner',
    role: 'Root Unix socket daemon (/run/aetherflow/runner.sock) with SO_PEERCRED + /proc/<pid>/exe auth, systemctl allowlists, package executor, WireGuard/NFS helpers, and DynamicUser=yes plugin units.',
    tone: 'emerald',
  },
  {
    name: 'af-transcode',
    binary: 'bin/af-transcode',
    role: 'Rust-native Jellyfin 12.4 transcode binary providing the JELLYFIN_FFMPEG shim, hardened af-transcode-worker.service daemon (PrivateNetwork=yes), and GPU capability probing.',
    tone: 'cyan',
  },
  {
    name: 'af-files',
    role: 'Capability-scoped Linux openat2 filesystem confinement primitives enforcing 0700 per-user McBrowser roots and traversal/symlink rejection.',
    tone: 'indigo',
  },
  {
    name: 'af-db',
    role: 'Bundled rusqlite WAL engine with split 1-writer / 8-reader pools, SQLite session & JWT revocation store (no Redis), migrations, and enc:v1: AES-256-GCM encryption.',
    tone: 'violet',
  },
  {
    name: 'af-services',
    role: '77-package catalog & update watcher, native XML/INI/JSON/TOML/YAML/SQLite config mutators, af-heal service watchdog, backup scheduler, and MediaFlow worker.',
    tone: 'violet',
  },
  {
    name: 'af-release',
    role: 'Pull-based atomic release engine (Deploy, Rollback, Cleanup, MigrateSystemd) with SHA-256 + Rekor v1/v2 Sigstore/SLSA v1 checks, WAL-safe snapshots, and /proc/<pid>/exe verification.',
    tone: 'amber',
  },
  {
    name: 'af-host',
    role: 'Versioned backup manifests (af-host.backup-manifest.v1), WAL-consistent VACUUM INTO snapshots, chunked archives, confirmed staged restore, and host maintenance tools.',
    tone: 'amber',
  },
  {
    name: 'af-cli',
    binary: 'bin/af',
    role: 'Unified administrative CLI for packages, systemd services, disk quotas (setdisk), sandbox drop-ins, releases, backups, hosts DNS, af cluster diagnose, and af provision.',
    tone: 'indigo',
  },
  {
    name: 'af-hardware',
    role: 'Zero-fork sysinfo & /proc/diskstats telemetry collector plus dynamic libloading FFI to libnvidia-ml.so.1 and DRM sysfs for GPU metrics.',
    tone: 'cyan',
  },
  {
    name: 'af-librespeed',
    binary: 'bin/speedtest-backend',
    role: 'Native Rust LibreSpeed backend replacing Go speedtest-go, with HMAC loopback proxy auth, SQLite WAL telemetry, BoltDB v2 auto-migration, and PNG result badges.',
    tone: 'emerald',
  },
  {
    name: 'af-models',
    role: 'Shared serde wire contracts, catalog schemas, hardware telemetry structs, and runner IPC request/response payloads.',
    tone: 'fuchsia',
  },
];

export const frontendCrates: CrateEntry[] = [
  {
    name: 'af-web-core',
    role: 'Shared API/WebSocket client policies, locale catalogs, form draft persistence, chart/topology algorithms, and target-gated native unit tests.',
    tone: 'violet',
  },
  {
    name: 'af-web-worker',
    role: 'Dedicated WebAssembly worker modules offloading background search, sorting, hashing, and chunked file uploads off the UI thread.',
    tone: 'cyan',
  },
  {
    name: 'af-web-ui',
    role: 'Accessible Leptos component kit: flat .af-* controls, data ledgers, syntax-highlighted code editor, telemetry charts, and topology views with CI drift enforcement.',
    tone: 'indigo',
  },
  {
    name: 'af-web-app',
    binary: 'web/dist',
    role: 'Application shell, authentication, OIDC consent, public shares, and all 16 dashboard tabs compiled with Trunk and staged into external web/dist.',
    tone: 'fuchsia',
  },
];

export const peerClusteringContent = {
  eyebrow: 'Flagship in v4.0.0',
  title: 'Peer Clustering without Control-Plane Lock-In',
  subtitle:
    'Link independent AetherFlow hosts over an AetherFlow-managed afpeer0 WireGuard tunnel. Every server remains sovereign with zero access granted by default, explicit 8-area permissions, health-gated NFSv4.2 media federation, and distributed Jellyfin 12.4 transcoding.',
  pillars: [
    {
      title: 'Six-Digit Pairing & SSRF Guard',
      detail:
        'Single-use 10-minute pairing windows initiate over OS-trusted HTTPS with DNS-pinned SSRF protection (blocking loopback, metadata, and private ranges unless AF_PEER_ALLOW_PRIVATE_PAIRING_URLS=true). Operators confirm matching six-digit verification codes on both dashboards before afpeer0 is linked.',
      meta: 'afpeer0 · 10.231.0.0/16 · UDP 51821',
      tone: 'cyan' as AccentTone,
    },
    {
      title: 'Zero-Access Default & 8 Grant Areas',
      detail:
        'Pairing establishes an encrypted tunnel with None across all 8 scopes. Grant Read-only or Read & write per direction (inbound/outbound). Revoking an inbound grant enforces locally right away and cancels active management WebSockets, HTTP proxy streams, and transcode jobs in under 1 second.',
      meta: 'TCP 9443 on afpeer0 · < 1s revocation',
      tone: 'indigo' as AccentTone,
    },
    {
      title: 'Health-Gated NFSv4.2 Storage Federation',
      detail:
        'Export real directories inside AF_ALLOWED_FS_ROOTS (read-only root_squash by default, opt-in writable all_squash) bound exclusively to afpeer0. Consuming hosts mount at /mnt/af-peers/<link>/<export> and probe .af-peer-sentinel every 15s so offline libraries disappear cleanly instead of triggering empty-trash wipes.',
      meta: 'TCP 2049 on afpeer0 · 15s sentinel probe',
      tone: 'emerald' as AccentTone,
    },
    {
      title: 'Distributed Jellyfin 12.4 Transcoding',
      detail:
        'Offload ffmpeg jobs from a controller to paired workers running hardened af-transcode-worker.service (User=jellyfin, PrivateNetwork=yes, DevicePolicy=closed, secret-free /etc/aetherflow/transcode.env). Includes 1-second libx264 parity checks, version alignment probes, auto-clamped concurrency, and automatic local fallback.',
      meta: 'af-transcode shim · Jellyfin 12.4 only',
      tone: 'fuchsia' as AccentTone,
    },
  ],
  grantAreas: [
    { area: 'services', desc: 'Service controls, logs, plugins, Approval Inbox & Streaming' },
    { area: 'marketplace', desc: 'Catalog installs, updates, uninstalls & blueprints' },
    { area: 'settings', desc: 'Server settings, backups, notifications & FlowAI' },
    { area: 'files', desc: 'McBrowser uploads, editing, archives & FileShare' },
    { area: 'users', desc: 'User accounts, roles, quotas & Streaming user links' },
    { area: 'network', desc: 'WireGuard wg0, Tailscale, ingress & bandwidth QoS' },
    { area: 'updates', desc: 'AetherFlow self-updates & narrowed jellyfin-ffmpeg alignment' },
    { area: 'transcoding', desc: 'MediaFlow queue, remote Jellyfin jobs & parity mounts' },
  ],
  diagnosticsCommand: 'sudo af cluster diagnose <link>',
  scopeNote:
    'Requires Debian 13 (trixie) on both servers with direct WireGuard UDP reachability. Peer clustering is designed for multi-server administration, media sharing, and Jellyfin 12.4 transcode offload—it does not provide high availability (HA) or automatic service failover. Migration 26 retires legacy master/worker clustering.',
};

export const installCommands = {
  interactive: {
    label: 'Interactive Bare-Metal Setup',
    badge: 'Debian 12/13 · Ubuntu 22.04/24.04 LTS',
    command: `sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get -y install git curl
sudo git clone https://github.com/McEveritts/AetherFlow.git /opt/AetherFlow
cd /opt/AetherFlow/setup
sudo bash AetherFlow-Setup`,
    note: 'Provisions APT repositories, Apache2 TLS ingress, SQLite state, and initial admin onboarding on a clean server.',
  },
  unattended: {
    label: 'Unattended & Step Repair',
    badge: 'Automated / CI-Friendly',
    command: `# Unattended bootstrap (--username creates the Linux owner account and records it in
# /root/information.info alongside the onboarding URL and bootstrap token path
# /var/lib/aetherflow/.setup-bootstrap-token; the first web admin account is created
# via web onboarding unless AETHERFLOW_WEB_ADMIN_PASSWORD is explicitly set)
sudo bash /opt/AetherFlow/setup/AetherFlow-Setup \\
  --unattended \\
  --username admin \\
  --domain node.example.com

# Repair specific step(s) on an existing installation while preserving saved configuration & database
# (Run with --list-steps to view available step IDs, such as build_modern for the control plane)
sudo bash /opt/AetherFlow/setup/AetherFlow-Setup --repair build_modern`,
    note: 'For fresh host provisioning use setup/AetherFlow-Setup; for repeatable Rust-native foundation steps and day-2 administration on an installed host, use af provision.',
  },
};

export interface ChangelogHighlight {
  badge: string;
  title: string;
  summary: string;
  bullets: string[];
  tone: AccentTone;
}

export const whatsNewHighlights: ChangelogHighlight[] = [
  {
    badge: 'v4.0.2 Security',
    title: 'Wave 0–2 Privilege-Boundary Hardening',
    summary:
      'Linear-time secret redaction, zeroized in-memory secrets, bounded subprocesses, and dirfd/fsuid filesystem confinement across the control plane.',
    bullets: [
      'UTF-8-safe line-classifier redaction with depth- and byte-budgeted JSON scrubbing',
      'SecretString/SecretBytes zeroization, 32-byte JWT_SECRET floor, and untrusted forwarding-header stripping',
      'Process-group-bounded installers, a 31-key release-config allowlist, and root-owned plugin trees',
    ],
    tone: 'amber',
  },
  {
    badge: 'v4.0.2 Transcoding & Topology',
    title: 'Load-Aware Transcoding & Tiered Topology Map',
    summary:
      'Silicon-verified, load- and latency-aware Jellyfin transcode dispatch, plus a three-tier Gateway → Service → Dependency service map.',
    bullets: [
      'vainfo and hardware Vulkan probing with remote_first / local_first / balanced dispatch policies',
      'Vulkan Compute HDR tone-mapping by default, Mesa shader cache, and cross-vendor backend adaptation',
      'Searchable, zoomable topology map with curved labelled links, a Map/List switcher, and a Service inspector',
    ],
    tone: 'violet',
  },
  {
    badge: 'v4 Core Subsystem',
    title: 'Peer Clustering & af-transcode',
    summary:
      'Decentralized server-to-server pairing over afpeer0 with zero-access default grants, NFSv4.2 media federation, and Jellyfin 12.4 transcode offload.',
    bullets: [
      'Six-digit HTTPS pairing with DNS-pinned SSRF guard and automatic wireguard-tools setup',
      'Zero-access default across 8 grant areas with < 1s WebSocket & HTTP stream revocation',
      'Health-gated NFSv4.2 media federation and distributed Jellyfin 12.4 ffmpeg offload',
    ],
    tone: 'cyan',
  },
  {
    badge: 'Zero-Go Cutover',
    title: '12-Crate Rust Control Plane & Native LibreSpeed',
    summary:
      'Memory-safe Rust binaries replace legacy Go and Redis daemons (0 .go files remain in the repository).',
    bullets: [
      'Native af-librespeed (bin/speedtest-backend) with SQLite WAL & BoltDB v2 migration',
      'Zero-CDN embedded OpenAPI 3.1 explorer and canonical root config/ layout',
      'Unified af CLI with af provision (14 Rust-native steps) and af cluster diagnose',
    ],
    tone: 'indigo',
  },
  {
    badge: 'Storage & Files',
    title: 'Native McBrowser & POSIX Quotas',
    summary:
      'Capability-scoped per-user file management built directly into the control plane via af-files and af-api::mcbrowser.',
    bullets: [
      'Linux openat2 confinement under 0700 per-user roots with traversal & symlink guards',
      '64 GiB resumable TUS uploads, ETag-guarded 10 MiB UTF-8 editor (45 syntax modes), 9 archive formats',
      'Integrated with Linux POSIX user disk quotas (af setdisk) and password-protected public shares',
    ],
    tone: 'indigo',
  },
  {
    badge: 'Security & Supply Chain',
    title: 'Zero-Sudo Runner, OIDC/PKCE & Sigstore v2',
    summary:
      'Hardened privilege boundaries and cryptographic release verification across every artifact.',
    bullets: [
      'Unprivileged aetherflow-api talking to root aetherflow-runner over /run/aetherflow/runner.sock',
      'Rekor v1 + v2 Sigstore/SLSA v1 verification, DynamicUser=yes plugin isolation, and bundled SQLite 3.54+',
      'OIDC provider with PKCE & device authorization flow plus DNS-rebinding SSRF pinning',
    ],
    tone: 'amber',
  },
];

export const footerColumns = [
  {
    heading: 'Documentation',
    links: [
      { label: 'Quickstart Guide', href: `${DOCS_BLOB_BASE}/docs/quickstart.md` },
      { label: 'System Architecture', href: `${DOCS_BLOB_BASE}/docs/architecture.md` },
      { label: 'Peer Clustering', href: `${DOCS_BLOB_BASE}/docs/peer-clustering.md` },
      { label: 'AetherMarketplace', href: `${DOCS_BLOB_BASE}/docs/marketplace.md` },
      { label: 'Unified Admin CLI (af)', href: `${DOCS_BLOB_BASE}/docs/rust-admin-cli.md` },
    ],
  },
  {
    heading: 'Subsystems',
    links: [
      { label: 'Native McBrowser', href: `${DOCS_BLOB_BASE}/docs/mcbrowser.md` },
      { label: 'Streaming History Contract', href: `${DOCS_BLOB_BASE}/docs/streaming-history-contract.md` },
      { label: 'Network: WireGuard & Tailscale', href: `${DOCS_BLOB_BASE}/docs/network-vpn.md` },
      { label: 'FlowAI Assistant', href: `${DOCS_BLOB_BASE}/docs/flowai.md` },
      { label: 'Self-Update & Rollbacks', href: `${DOCS_BLOB_BASE}/docs/self-update.md` },
    ],
  },
  {
    heading: 'Project & Security',
    links: [
      { label: 'GitHub Repository', href: REPO_URL },
      { label: 'GitHub Releases (v4.0.2)', href: RELEASES_URL },
      { label: 'Changelog', href: `${DOCS_BLOB_BASE}/CHANGELOG.md` },
      { label: 'Security Policy (SECURITY.md)', href: `${DOCS_BLOB_BASE}/SECURITY.md` },
      { label: 'Threat Model', href: `${DOCS_BLOB_BASE}/docs/threat_model.md` },
      { label: 'License (GPL-3.0)', href: `${DOCS_BLOB_BASE}/LICENSE.md` },
    ],
  },
];
