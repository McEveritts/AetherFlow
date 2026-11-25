'use client';

import { useState } from 'react';
import {
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Cpu,
  HardDrive,
  Moon,
  Network,
  ShieldCheck,
  Sun,
  Tag,
} from 'lucide-react';
import { heroContent } from '@/content/home';
import type { ScreenshotTheme } from '@/lib/media';

interface HeroSectionProps {
  heroScreenshots: {
    dark: string | null;
    light: string | null;
  };
}

function HeroFallbackCanvas({ theme }: { theme: ScreenshotTheme }) {
  const isLight = theme === 'light';
  return (
    <div
      className={`relative flex aspect-[16/9] w-full flex-col justify-between overflow-hidden p-5 sm:p-8 ${
        isLight ? 'bg-[#f4f6fb] text-slate-900' : 'bg-[#070a12] text-white'
      }`}
    >
      <div
        className="pointer-events-none absolute inset-0 opacity-70"
        style={{
          background: isLight
            ? 'radial-gradient(ellipse 65% 55% at 15% 20%, rgba(99,102,241,0.12), transparent 70%), radial-gradient(ellipse 65% 55% at 85% 80%, rgba(14,165,233,0.1), transparent 70%)'
            : 'radial-gradient(ellipse 65% 55% at 15% 20%, rgba(34,211,238,0.14), transparent 70%), radial-gradient(ellipse 65% 55% at 85% 80%, rgba(217,70,239,0.12), transparent 70%)',
        }}
      />
      <div className="relative grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
        {[
          {
            label: 'Control Plane',
            val: 'aetherflow-api',
            sub: '12 Rust crates · WAL',
            color: isLight ? 'text-indigo-700' : 'text-indigo-300',
          },
          {
            label: 'WASM Interface',
            val: '16 Tabs',
            sub: 'Leptos web/dist',
            color: isLight ? 'text-violet-700' : 'text-violet-300',
          },
          {
            label: 'Peer Mesh',
            val: 'afpeer0',
            sub: 'WireGuard + NFSv4.2',
            color: isLight ? 'text-cyan-700' : 'text-cyan-300',
          },
          {
            label: 'Runner Boundary',
            val: 'runner.sock',
            sub: 'Zero-sudo · Active',
            color: isLight ? 'text-emerald-700' : 'text-emerald-300',
          },
        ].map((card) => (
          <div
            key={card.label}
            className={`rounded-xl border p-3 sm:p-4 ${
              isLight
                ? 'border-slate-200 bg-white/90 shadow-xs'
                : 'border-white/10 bg-[#0d1220]/90'
            }`}
          >
            <div
              className={`font-mono text-[10px] uppercase tracking-wider ${
                isLight ? 'text-slate-500' : 'text-slate-400'
              }`}
            >
              {card.label}
            </div>
            <div className={`mt-1 text-base font-bold sm:text-xl ${card.color}`}>
              {card.val}
            </div>
            <div
              className={`mt-1 text-[11px] ${
                isLight ? 'text-slate-600' : 'text-slate-400'
              }`}
            >
              {card.sub}
            </div>
          </div>
        ))}
      </div>

      <div className="relative mt-4 grid flex-1 grid-cols-1 gap-3 sm:grid-cols-3 sm:gap-4">
        <div
          className={`col-span-2 flex flex-col justify-between rounded-xl border p-4 ${
            isLight
              ? 'border-indigo-200 bg-white/95'
              : 'border-indigo-400/20 bg-[#0b101d]/90'
          }`}
        >
          <div className="flex items-center justify-between text-xs">
            <span
              className={`inline-flex items-center gap-1.5 font-mono ${
                isLight ? 'text-indigo-700' : 'text-indigo-200'
              }`}
            >
              <Cpu className="h-3.5 w-3.5 text-cyan-500" />
              Telemetry Stream · UTC
            </span>
            <span
              className={`font-mono ${
                isLight ? 'text-emerald-700' : 'text-emerald-400'
              }`}
            >
              WS Frame-0 Connected
            </span>
          </div>
          <svg
            viewBox="0 0 420 110"
            className="mt-3 h-24 w-full sm:h-32"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id="heroMockArea" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#6366f1" stopOpacity="0.35" />
                <stop offset="100%" stopColor="#6366f1" stopOpacity="0" />
              </linearGradient>
            </defs>
            <path
              d="M0 84 C36 74, 64 58, 102 64 C144 70, 172 34, 214 42 C258 50, 294 22, 336 30 C372 36, 396 24, 420 20 L420 110 L0 110 Z"
              fill="url(#heroMockArea)"
            />
            <path
              d="M0 84 C36 74, 64 58, 102 64 C144 70, 172 34, 214 42 C258 50, 294 22, 336 30 C372 36, 396 24, 420 20"
              fill="none"
              stroke="#6366f1"
              strokeWidth="2.5"
            />
            <path
              d="M0 94 C44 88, 92 78, 138 82 C188 86, 232 62, 276 68 C326 74, 372 52, 420 56"
              fill="none"
              stroke="#06b6d4"
              strokeWidth="2"
              strokeDasharray="4 4"
            />
          </svg>
        </div>

        <div
          className={`hidden flex-col justify-between rounded-xl border p-4 sm:flex ${
            isLight
              ? 'border-slate-200 bg-white/95'
              : 'border-white/10 bg-[#0b101d]/90'
          }`}
        >
          <div
            className={`font-mono text-xs ${
              isLight ? 'text-slate-700' : 'text-slate-300'
            }`}
          >
            Managed Units
          </div>
          <div className="space-y-2 text-xs">
            {[
              { name: 'aetherflow-api.service', icon: ShieldCheck, status: 'active' },
              { name: 'aetherflow-runner.service', icon: HardDrive, status: 'active' },
              { name: 'wg-quick@afpeer0', icon: Network, status: 'linked' },
            ].map((u) => (
              <div
                key={u.name}
                className={`flex items-center justify-between rounded-lg border px-2.5 py-2 ${
                  isLight
                    ? 'border-slate-200 bg-slate-50'
                    : 'border-white/[0.06] bg-white/[0.02]'
                }`}
              >
                <span
                  className={`truncate font-mono text-[11px] ${
                    isLight ? 'text-slate-800' : 'text-slate-200'
                  }`}
                >
                  {u.name}
                </span>
                <span
                  className={`ml-2 shrink-0 rounded-full px-2 py-0.5 font-mono text-[10px] ${
                    isLight
                      ? 'bg-emerald-100 text-emerald-800'
                      : 'bg-emerald-500/15 text-emerald-300'
                  }`}
                >
                  {u.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export function HeroSection({ heroScreenshots }: HeroSectionProps) {
  const [previewTheme, setPreviewTheme] = useState<ScreenshotTheme>('dark');
  const [failedThemes, setFailedThemes] = useState<
    Partial<Record<ScreenshotTheme, boolean>>
  >({});

  const activeSrc = heroScreenshots[previewTheme] ?? null;
  const showImage = Boolean(activeSrc) && !failedThemes[previewTheme];

  return (
    <section
      aria-labelledby="hero-heading"
      className="relative overflow-hidden pb-14 pt-8 sm:pb-20 sm:pt-10 lg:pt-12"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="mx-auto max-w-5xl text-center">
          <a
            href={heroContent.releasesCta.href}
            target="_blank"
            rel="noopener noreferrer"
            className="group inline-flex max-w-full items-center gap-2 rounded-full border border-indigo-400/35 bg-indigo-500/10 px-3.5 py-1.5 font-mono text-[11px] font-medium text-indigo-100 shadow-[0_0_24px_rgba(99,102,241,0.2)] transition-colors hover:border-cyan-400/50 hover:bg-indigo-500/20 sm:px-4 sm:text-xs"
          >
            <span
              className="h-2 w-2 shrink-0 rounded-full bg-emerald-400 shadow-[0_0_10px_#34d399]"
              aria-hidden="true"
            />
            <span className="sm:hidden">v4.0.1 · Rust Control Plane &amp; WASM</span>
            <span className="hidden sm:inline">{heroContent.versionPill}</span>
            <ArrowRight
              className="h-3.5 w-3.5 shrink-0 text-indigo-300 transition-transform group-hover:translate-x-0.5"
              aria-hidden="true"
            />
          </a>

          <h1
            id="hero-heading"
            className="mx-auto mt-5 max-w-4xl text-[2.15rem] font-extrabold leading-[1.08] tracking-tight text-white sm:text-5xl lg:text-[3.75rem] lg:leading-[1.05]"
          >
            {heroContent.headlineLead}{' '}
            <span className="obs-gradient-text block sm:inline">
              {heroContent.headlineAccent}
            </span>
          </h1>

          <p className="mx-auto mt-4 max-w-3xl text-[15px] leading-relaxed text-slate-300 sm:mt-5 sm:text-base lg:text-lg lg:leading-relaxed">
            {heroContent.subheadline}
          </p>

          <div className="mt-6 flex flex-col items-stretch justify-center gap-2.5 sm:mt-7 sm:flex-row sm:items-center sm:gap-3">
            <a
              href={heroContent.primaryCta.href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-violet-600 px-6 py-3 text-sm font-semibold text-white shadow-[0_8px_28px_rgba(99,102,241,0.4)] transition-all hover:-translate-y-0.5 hover:brightness-110 sm:text-[15px]"
            >
              <span>{heroContent.primaryCta.label}</span>
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </a>

            <a
              href={heroContent.secondaryCta.href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/15 bg-white/[0.05] px-6 py-3 text-sm font-semibold text-slate-100 backdrop-blur-md transition-all hover:-translate-y-0.5 hover:border-cyan-400/45 hover:bg-white/[0.09] sm:text-[15px]"
            >
              <BookOpen className="h-4 w-4 text-cyan-300" aria-hidden="true" />
              <span>{heroContent.secondaryCta.label}</span>
            </a>

            <a
              href={heroContent.releasesCta.href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-transparent px-4 py-2.5 text-sm font-medium text-slate-300 transition-colors hover:bg-white/[0.05] hover:text-white"
            >
              <Tag className="h-4 w-4 text-violet-300" aria-hidden="true" />
              <span>{heroContent.releasesCta.label}</span>
            </a>
          </div>

          <ul className="mt-5 flex flex-wrap items-center justify-center gap-2 text-xs text-slate-300">
            {heroContent.trustPills.map((pill) => (
              <li
                key={pill}
                className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 font-mono text-[11px]"
              >
                <CheckCircle2
                  className="h-3.5 w-3.5 shrink-0 text-emerald-400"
                  aria-hidden="true"
                />
                <span>{pill}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Hero Obsidian Dashboard Showcase */}
        <div className="relative mx-auto mt-8 max-w-6xl sm:mt-10">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -inset-x-6 -top-8 bottom-8 -z-10 rounded-[2rem] bg-gradient-to-r from-cyan-500/20 via-indigo-500/25 to-fuchsia-500/20 blur-3xl opacity-60"
          />

          <div className="obs-glass-chromatic overflow-hidden rounded-2xl">
            {/* Window Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.08] bg-[#060912]/90 px-4 py-2.5">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-rose-500/75" aria-hidden="true" />
                <span className="h-2.5 w-2.5 rounded-full bg-amber-400/75" aria-hidden="true" />
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/75" aria-hidden="true" />
                <span className="ml-2 truncate font-mono text-xs text-slate-400">
                  https://node.example.com/?tab=overview
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div
                  role="group"
                  aria-label="Hero dashboard preview theme"
                  className="inline-flex items-center rounded-lg border border-white/10 bg-white/[0.04] p-0.5"
                >
                  <button
                    type="button"
                    aria-pressed={previewTheme === 'dark'}
                    onClick={() => setPreviewTheme('dark')}
                    className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 font-mono text-[11px] font-medium transition-colors ${
                      previewTheme === 'dark'
                        ? 'bg-indigo-500/30 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Moon className="h-3 w-3" aria-hidden="true" />
                    <span>Dark</span>
                  </button>
                  <button
                    type="button"
                    aria-pressed={previewTheme === 'light'}
                    onClick={() => setPreviewTheme('light')}
                    className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 font-mono text-[11px] font-medium transition-colors ${
                      previewTheme === 'light'
                        ? 'bg-amber-400/25 text-amber-100'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Sun className="h-3 w-3" aria-hidden="true" />
                    <span>Light</span>
                  </button>
                </div>
                <span className="hidden rounded-md border border-indigo-400/25 bg-indigo-500/10 px-2 py-0.5 font-mono text-[11px] text-indigo-200 md:inline-flex">
                  Leptos WASM · 16 Tabs
                </span>
                <span className="hidden items-center gap-1.5 rounded-md border border-emerald-400/25 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] text-emerald-300 sm:inline-flex">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
                  runner.sock ok
                </span>
              </div>
            </div>

            {showImage && activeSrc ? (
              <div
                className={`relative aspect-[16/9] w-full ${
                  previewTheme === 'light' ? 'bg-slate-100' : 'bg-[#07090e]'
                }`}
              >
                <img
                  key={`${previewTheme}-${activeSrc}`}
                  src={activeSrc}
                  alt={`AetherFlow v4.0.1 Overview dashboard in ${previewTheme} theme displaying live hardware telemetry, GPU status, and managed systemd services`}
                  width={2560}
                  height={1440}
                  onError={() =>
                    setFailedThemes((prev) => ({ ...prev, [previewTheme]: true }))
                  }
                  className="h-full w-full object-cover object-top"
                />
              </div>
            ) : (
              <HeroFallbackCanvas theme={previewTheme} />
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
