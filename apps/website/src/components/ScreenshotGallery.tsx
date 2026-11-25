'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Bell,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Expand,
  Film,
  FolderLock,
  Globe,
  Inbox,
  Layers,
  Moon,
  Network,
  Package,
  PieChart,
  ScrollText,
  Server,
  Settings,
  Share2,
  ShieldCheck,
  Sparkles,
  Sun,
  Users,
  X,
  type LucideIcon,
} from 'lucide-react';
import {
  galleryGroups,
  galleryViews,
  type GalleryGroupId,
  type GalleryScreenId,
  type GalleryView,
} from '@/content/home';
import type { ScreenshotTheme, ThemedScreenshotSet } from '@/lib/media';

interface ScreenshotGalleryProps {
  screenshots: ThemedScreenshotSet;
}

const TAB_ICONS: Record<GalleryScreenId, LucideIcon> = {
  overview: Layers,
  inbox: Inbox,
  services: Server,
  marketplace: Package,
  notifications: Bell,
  streaming: Activity,
  mediaflow: Film,
  mcbrowser: FolderLock,
  fileshare: Share2,
  cluster: Network,
  network: Globe,
  flowai: Sparkles,
  security: ShieldCheck,
  users: Users,
  quotas: PieChart,
  audit: ScrollText,
  settings: Settings,
};

function ViewFallbackPanel({
  view,
  theme,
  hasAlternateTheme,
  onSwitchTheme,
}: {
  view: GalleryView;
  theme: ScreenshotTheme;
  hasAlternateTheme: boolean;
  onSwitchTheme: () => void;
}) {
  const isLight = theme === 'light';
  return (
    <div
      className={`relative flex aspect-[16/9] w-full flex-col justify-between overflow-hidden p-5 sm:p-8 ${
        isLight ? 'bg-[#f4f6fb] text-slate-900' : 'bg-[#070a12] text-white'
      }`}
    >
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background: isLight
            ? 'radial-gradient(ellipse 60% 50% at 18% 24%, rgba(99,102,241,0.12), transparent 70%), radial-gradient(ellipse 55% 50% at 84% 78%, rgba(14,165,233,0.1), transparent 72%)'
            : 'radial-gradient(ellipse 60% 50% at 18% 24%, rgba(99,102,241,0.16), transparent 70%), radial-gradient(ellipse 55% 50% at 84% 78%, rgba(34,211,238,0.12), transparent 72%)',
        }}
      />
      <div className="relative flex flex-wrap items-center justify-between gap-2">
        <div
          className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1 font-mono text-xs ${
            isLight
              ? 'border-indigo-300 bg-indigo-50 text-indigo-800'
              : 'border-indigo-400/30 bg-indigo-500/15 text-indigo-200'
          }`}
        >
          <span className="h-2 w-2 rounded-full bg-cyan-400" aria-hidden="true" />
          <span>{view.route}</span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`rounded-md border px-2.5 py-1 font-mono text-[11px] ${
              isLight
                ? 'border-slate-300 bg-white text-slate-700'
                : 'border-white/10 bg-white/[0.04] text-slate-300'
            }`}
          >
            {isLight ? 'Light' : 'Dark'} theme · {view.label}
          </span>
          {hasAlternateTheme && (
            <button
              type="button"
              onClick={onSwitchTheme}
              className={`rounded-md border px-2.5 py-1 font-mono text-[11px] font-semibold transition-colors ${
                isLight
                  ? 'border-indigo-300 bg-indigo-600 text-white hover:bg-indigo-700'
                  : 'border-amber-400/40 bg-amber-500/15 text-amber-100 hover:bg-amber-500/25'
              }`}
            >
              Switch to {isLight ? 'Dark' : 'Light'}
            </button>
          )}
        </div>
      </div>

      <div className="relative my-auto py-4">
        <p
          className={`font-mono text-xs uppercase tracking-[0.16em] ${
            isLight ? 'text-indigo-700' : 'text-cyan-300'
          }`}
        >
          Leptos Rust WASM View
        </p>
        <h4
          className={`mt-2 max-w-xl text-xl font-bold sm:text-2xl ${
            isLight ? 'text-slate-900' : 'text-white'
          }`}
        >
          {view.tagline}
        </h4>
        <p
          className={`mt-2 max-w-2xl text-xs leading-relaxed sm:text-sm ${
            isLight ? 'text-slate-600' : 'text-slate-300'
          }`}
        >
          {view.description}
        </p>
        <div className="mt-5 grid grid-cols-1 gap-2.5 sm:grid-cols-3">
          {view.highlights.map((item) => (
            <div
              key={item}
              className={`flex items-center gap-2 rounded-xl border px-3.5 py-2.5 text-xs ${
                isLight
                  ? 'border-slate-200 bg-white/90 text-slate-800'
                  : 'border-white/10 bg-[#0d1322]/90 text-slate-200'
              }`}
            >
              <CheckCircle2
                className={`h-3.5 w-3.5 shrink-0 ${
                  isLight ? 'text-emerald-600' : 'text-emerald-400'
                }`}
                aria-hidden="true"
              />
              <span>{item}</span>
            </div>
          ))}
        </div>
      </div>

      <div
        className={`relative flex items-center justify-between border-t pt-3 font-mono text-[11px] ${
          isLight
            ? 'border-slate-200 text-slate-500'
            : 'border-white/[0.08] text-slate-400'
        }`}
      >
        <span>aetherflow-api v4.0.1 · external web/dist</span>
        <span>
          screenshots/{theme}/{view.id}.png
        </span>
      </div>
    </div>
  );
}

export function ScreenshotGallery({ screenshots }: ScreenshotGalleryProps) {
  const [selectedGroup, setSelectedGroup] = useState<'all' | GalleryGroupId>('all');
  const [activeId, setActiveId] = useState<GalleryScreenId>('overview');
  const [theme, setTheme] = useState<ScreenshotTheme>('dark');
  const [failedKeys, setFailedKeys] = useState<Record<string, boolean>>({});
  const [lightboxOpen, setLightboxOpen] = useState(false);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  const visibleViews = useMemo(() => {
    if (selectedGroup === 'all') return galleryViews;
    return galleryViews.filter((view) => view.group === selectedGroup);
  }, [selectedGroup]);

  const activeIndexInGroup = useMemo(() => {
    const idx = visibleViews.findIndex((v) => v.id === activeId);
    return idx >= 0 ? idx : 0;
  }, [visibleViews, activeId]);

  const activeView = visibleViews[activeIndexInGroup] ?? galleryViews[0];
  const activeKey = `${theme}:${activeView.id}`;
  const activeSrc = screenshots[theme][activeView.id] ?? null;
  const canDisplayImage = Boolean(activeSrc) && !failedKeys[activeKey];

  const alternateTheme: ScreenshotTheme = theme === 'dark' ? 'light' : 'dark';
  const hasAlternateTheme =
    Boolean(screenshots[alternateTheme][activeView.id]) &&
    !failedKeys[`${alternateTheme}:${activeView.id}`];

  const groupCounts = useMemo(() => {
    const counts: Record<GalleryGroupId, number> = {
      operations: 0,
      media: 0,
      infrastructure: 0,
      governance: 0,
    };
    for (const v of galleryViews) {
      counts[v.group] += 1;
    }
    return counts;
  }, []);

  function selectGroup(group: 'all' | GalleryGroupId) {
    setSelectedGroup(group);
    if (group !== 'all') {
      const nextViews = galleryViews.filter((v) => v.group === group);
      if (!nextViews.some((v) => v.id === activeId) && nextViews[0]) {
        setActiveId(nextViews[0].id);
      }
    }
  }

  function stepScreen(delta: number) {
    const nextIdx =
      (activeIndexInGroup + delta + visibleViews.length) % visibleViews.length;
    setActiveId(visibleViews[nextIdx].id);
  }

  useEffect(() => {
    if (!lightboxOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setLightboxOpen(false);
      else if (e.key === 'ArrowRight') {
        e.preventDefault();
        stepScreen(1);
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        stepScreen(-1);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  });

  function handleTabKeyDown(
    e: React.KeyboardEvent<HTMLButtonElement>,
    idx: number
  ) {
    let nextIdx: number | null = null;
    if (e.key === 'ArrowRight') nextIdx = (idx + 1) % visibleViews.length;
    else if (e.key === 'ArrowLeft')
      nextIdx = (idx - 1 + visibleViews.length) % visibleViews.length;
    else if (e.key === 'Home') nextIdx = 0;
    else if (e.key === 'End') nextIdx = visibleViews.length - 1;

    if (nextIdx !== null) {
      e.preventDefault();
      setActiveId(visibleViews[nextIdx].id);
      tabRefs.current[nextIdx]?.focus();
    }
  }

  const counterLabel = `${String(activeIndexInGroup + 1).padStart(2, '0')} / ${String(
    visibleViews.length
  ).padStart(2, '0')}`;

  return (
    <section
      id="gallery"
      aria-labelledby="gallery-heading"
      className="scroll-mt-20 border-t border-white/[0.07] py-20 sm:py-28"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="max-w-3xl">
          <p className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-violet-300">
            Leptos Rust WASM Interface · Dark &amp; Light Themes
          </p>
          <h2
            id="gallery-heading"
            className="mt-2 text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-[2.6rem]"
          >
            Tour all 16 dashboard tabs plus Security &amp; 2FA
          </h2>
          <p className="mt-3 text-base leading-relaxed text-slate-300">
            Compiled from four Rust WebAssembly crates into static assets served straight from{' '}
            <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-indigo-200">
              web/dist
            </code>
            . Filter by operational domain, step through all {galleryViews.length} views, and compare Dark and Light themes.
          </p>
        </div>

        {/* Group Filter Strip + Accessible Dark / Light Theme Switch */}
        <div className="mt-7 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div
            role="group"
            aria-label="Filter dashboard screenshots by section"
            className="obs-scroll flex gap-2 overflow-x-auto pb-1"
          >
            <button
              type="button"
              aria-pressed={selectedGroup === 'all'}
              onClick={() => selectGroup('all')}
              className={`shrink-0 rounded-xl border px-3.5 py-1.5 font-mono text-xs font-semibold transition-colors ${
                selectedGroup === 'all'
                  ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-100'
                  : 'border-white/[0.08] bg-white/[0.025] text-slate-300 hover:border-white/20 hover:text-white'
              }`}
            >
              All Screens ({galleryViews.length})
            </button>
            {galleryGroups.map((group) => (
              <button
                key={group.id}
                type="button"
                aria-pressed={selectedGroup === group.id}
                onClick={() => selectGroup(group.id)}
                className={`shrink-0 rounded-xl border px-3.5 py-1.5 font-mono text-xs font-medium transition-colors ${
                  selectedGroup === group.id
                    ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-100'
                    : 'border-white/[0.08] bg-white/[0.025] text-slate-300 hover:border-white/20 hover:text-white'
                }`}
              >
                {group.label} ({groupCounts[group.id]})
              </button>
            ))}
          </div>

          <div
            role="group"
            aria-label="Dashboard screenshot color theme"
            className="inline-flex shrink-0 self-start rounded-xl border border-white/12 bg-white/[0.04] p-1 lg:self-auto"
          >
            <button
              type="button"
              aria-pressed={theme === 'dark'}
              onClick={() => setTheme('dark')}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                theme === 'dark'
                  ? 'bg-indigo-500/30 text-white shadow-[0_0_14px_rgba(99,102,241,0.3)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Moon className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Dark</span>
            </button>
            <button
              type="button"
              aria-pressed={theme === 'light'}
              onClick={() => setTheme('light')}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                theme === 'light'
                  ? 'bg-amber-400/25 text-amber-100 shadow-[0_0_14px_rgba(251,191,36,0.22)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Sun className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Light</span>
            </button>
          </div>
        </div>

        {/* Accessible Screen Tab Strip */}
        <div
          role="tablist"
          aria-label="Dashboard screenshot views"
          className="obs-scroll mt-3.5 flex gap-2 overflow-x-auto pb-2"
        >
          {visibleViews.map((view, idx) => {
            const Icon = TAB_ICONS[view.id];
            const selected = view.id === activeView.id;
            return (
              <button
                key={view.id}
                ref={(el) => {
                  tabRefs.current[idx] = el;
                }}
                id={`gallery-tab-${view.id}`}
                role="tab"
                type="button"
                aria-selected={selected}
                aria-controls={`gallery-panel-${view.id}`}
                tabIndex={selected ? 0 : -1}
                onClick={() => setActiveId(view.id)}
                onKeyDown={(e) => handleTabKeyDown(e, idx)}
                className={`inline-flex shrink-0 items-center gap-2 rounded-xl border px-3.5 py-2 text-xs font-medium transition-all sm:text-sm ${
                  selected
                    ? 'border-indigo-400/55 bg-indigo-500/20 text-white shadow-[0_0_20px_rgba(99,102,241,0.25)]'
                    : 'border-white/[0.08] bg-white/[0.03] text-slate-300 hover:border-white/20 hover:bg-white/[0.06] hover:text-white'
                }`}
              >
                <Icon
                  className={`h-3.5 w-3.5 sm:h-4 sm:w-4 ${
                    selected ? 'text-cyan-300' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
                <span>{view.label}</span>
              </button>
            );
          })}
        </div>

        {/* Active Panel */}
        <div
          id={`gallery-panel-${activeView.id}`}
          role="tabpanel"
          aria-labelledby={`gallery-tab-${activeView.id}`}
          className="mt-5"
        >
          <div className="obs-glass-chromatic overflow-hidden rounded-2xl">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.08] bg-[#060912]/90 px-4 py-2.5">
              <div className="flex min-w-0 items-center gap-2">
                <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-rose-500/75" aria-hidden="true" />
                <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-amber-400/75" aria-hidden="true" />
                <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-emerald-400/75" aria-hidden="true" />
                <span className="ml-2 truncate font-mono text-xs text-slate-200">
                  {activeView.label}{' '}
                  <span className="hidden text-slate-400 sm:inline">
                    — {activeView.route}
                  </span>
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 font-mono text-[11px] text-slate-300 tabular-nums">
                  {counterLabel}
                </span>
                <div className="inline-flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => stepScreen(-1)}
                    aria-label="Previous dashboard screen"
                    className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-white/10 bg-white/[0.04] text-slate-200 transition-colors hover:border-indigo-400/45 hover:text-white"
                  >
                    <ChevronLeft className="h-4 w-4" aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    onClick={() => stepScreen(1)}
                    aria-label="Next dashboard screen"
                    className="inline-flex h-7 w-7 items-center justify-center rounded-lg border border-white/10 bg-white/[0.04] text-slate-200 transition-colors hover:border-indigo-400/45 hover:text-white"
                  >
                    <ChevronRight className="h-4 w-4" aria-hidden="true" />
                  </button>
                </div>
                {canDisplayImage && (
                  <button
                    type="button"
                    onClick={() => setLightboxOpen(true)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.05] px-2.5 py-1 font-mono text-[11px] text-slate-200 transition-colors hover:border-cyan-400/40 hover:text-white"
                  >
                    <Expand className="h-3.5 w-3.5" aria-hidden="true" />
                    <span className="hidden sm:inline">Full resolution</span>
                  </button>
                )}
              </div>
            </div>

            {canDisplayImage && activeSrc ? (
              <div
                className={`relative aspect-[16/9] w-full ${
                  theme === 'light' ? 'bg-slate-100' : 'bg-[#07090e]'
                }`}
              >
                <img
                  key={activeKey}
                  src={activeSrc}
                  alt={`AetherFlow v4.0.1 ${activeView.label} dashboard view (${theme} theme) — ${activeView.tagline}`}
                  width={2560}
                  height={1440}
                  onError={() =>
                    setFailedKeys((prev) => ({ ...prev, [activeKey]: true }))
                  }
                  className="h-full w-full object-cover object-top"
                />
              </div>
            ) : (
              <ViewFallbackPanel
                view={activeView}
                theme={theme}
                hasAlternateTheme={hasAlternateTheme}
                onSwitchTheme={() => setTheme(alternateTheme)}
              />
            )}

            <div className="flex flex-col justify-between gap-4 border-t border-white/[0.08] bg-[#080c17]/90 p-5 sm:p-6 lg:flex-row lg:items-center">
              <div className="max-w-2xl">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-lg font-bold text-white">
                    {activeView.tagline}
                  </h3>
                  <span className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-slate-300">
                    {theme}
                  </span>
                </div>
                <p className="mt-1.5 text-sm leading-relaxed text-slate-300">
                  {activeView.description}
                </p>
              </div>
              <ul className="flex flex-wrap gap-2 lg:max-w-md lg:justify-end">
                {activeView.highlights.map((item) => (
                  <li
                    key={item}
                    className="rounded-lg border border-indigo-400/25 bg-indigo-500/10 px-3 py-1 font-mono text-xs text-indigo-200"
                  >
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Full-Resolution Lightbox Modal */}
      {lightboxOpen && canDisplayImage && activeSrc && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`${activeView.label} full-resolution preview (${theme} theme)`}
          onClick={() => setLightboxOpen(false)}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 backdrop-blur-md sm:p-8"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="relative max-h-[92vh] w-full max-w-[1440px] overflow-hidden rounded-2xl border border-indigo-400/35 bg-[#07090e] shadow-2xl"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 px-4 py-3">
              <span className="font-mono text-xs text-slate-200">
                {activeView.label} · {activeView.tagline} ({theme}) · {counterLabel}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setTheme(alternateTheme)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-white/[0.06] px-2.5 py-1 font-mono text-xs text-slate-200 hover:bg-white/15 hover:text-white"
                >
                  {theme === 'dark' ? (
                    <>
                      <Sun className="h-3.5 w-3.5 text-amber-300" aria-hidden="true" />
                      <span>Light</span>
                    </>
                  ) : (
                    <>
                      <Moon className="h-3.5 w-3.5 text-indigo-300" aria-hidden="true" />
                      <span>Dark</span>
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => stepScreen(-1)}
                  aria-label="Previous screen"
                  className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-white/15 bg-white/[0.06] text-slate-200 hover:bg-white/15 hover:text-white"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  onClick={() => stepScreen(1)}
                  aria-label="Next screen"
                  className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-white/15 bg-white/[0.06] text-slate-200 hover:bg-white/15 hover:text-white"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  onClick={() => setLightboxOpen(false)}
                  aria-label="Close full resolution preview"
                  className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-white/15 bg-white/[0.06] text-slate-200 hover:bg-white/15 hover:text-white"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
            <img
              key={`lb-${activeKey}`}
              src={activeSrc}
              alt={`AetherFlow v4.0.1 ${activeView.label} dashboard screenshot (${theme} theme) at full resolution`}
              className={`max-h-[82vh] w-full object-contain ${
                theme === 'light' ? 'bg-slate-100' : 'bg-[#07090e]'
              }`}
            />
          </div>
        </div>
      )}
    </section>
  );
}
