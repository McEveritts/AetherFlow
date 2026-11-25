'use client';

import { useMemo, useState } from 'react';
import { ArrowUpRight, Search, X } from 'lucide-react';
import type { CatalogApp, CatalogCategorySummary } from '@/lib/catalog';
import { DOCS_BLOB_BASE } from '@/content/home';

interface CatalogShowcaseProps {
  apps: CatalogApp[];
  categories: CatalogCategorySummary[];
  totalCount: number;
}

const CATEGORY_ACCENTS: Record<string, string> = {
  Media: 'border-indigo-400/30 bg-indigo-500/12 text-indigo-200',
  Downloaders: 'border-cyan-400/30 bg-cyan-500/12 text-cyan-200',
  Cloud: 'border-violet-400/30 bg-violet-500/12 text-violet-200',
  Network: 'border-emerald-400/30 bg-emerald-500/12 text-emerald-200',
  Utilities: 'border-fuchsia-400/30 bg-fuchsia-500/12 text-fuchsia-200',
  Monitoring: 'border-amber-400/30 bg-amber-500/12 text-amber-200',
  Security: 'border-emerald-400/30 bg-emerald-500/12 text-emerald-200',
  Automation: 'border-violet-400/30 bg-violet-500/12 text-violet-200',
  DevOps: 'border-indigo-400/30 bg-indigo-500/12 text-indigo-200',
};

export function CatalogShowcase({
  apps,
  categories,
  totalCount,
}: CatalogShowcaseProps) {
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [query, setQuery] = useState('');

  const filteredApps = useMemo(() => {
    const q = query.trim().toLowerCase();
    return apps.filter((app) => {
      if (selectedCategory !== 'All' && app.category !== selectedCategory) {
        return false;
      }
      if (!q) return true;
      return (
        app.label.toLowerCase().includes(q) ||
        app.name.toLowerCase().includes(q) ||
        app.description.toLowerCase().includes(q) ||
        app.service_name.toLowerCase().includes(q) ||
        app.category.toLowerCase().includes(q) ||
        (app.default_port > 0 && String(app.default_port).includes(q))
      );
    });
  }, [apps, selectedCategory, query]);

  const groupedByCategory = useMemo(() => {
    const map = new Map<string, CatalogApp[]>();
    for (const cat of categories) {
      map.set(cat.name, []);
    }
    for (const app of filteredApps) {
      const bucket = map.get(app.category) ?? [];
      bucket.push(app);
      map.set(app.category, bucket);
    }
    return Array.from(map.entries()).filter(([, list]) => list.length > 0);
  }, [categories, filteredApps]);

  return (
    <section
      id="catalog"
      aria-labelledby="catalog-heading"
      className="scroll-mt-20 border-t border-white/[0.07] py-20 sm:py-28"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div className="max-w-3xl">
            <p className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-fuchsia-300">
              AetherMarketplace · Built from config/packages.json
            </p>
            <h2
              id="catalog-heading"
              className="mt-2 text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-[2.6rem]"
            >
              All {totalCount} native Linux packages across {categories.length} categories
            </h2>
            <p className="mt-3 text-base leading-relaxed text-slate-300">
              Installed directly onto the host under <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-indigo-200">systemd</code>—serialized behind <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-indigo-200">.af-package-executor.flock</code> with locked Bash installers by default and 9 opt-in declarative Rust recipes.
            </p>
          </div>

          <a
            href={`${DOCS_BLOB_BASE}/docs/marketplace.md`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex shrink-0 items-center gap-1.5 self-start rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-fuchsia-400/45 hover:text-white lg:self-auto"
          >
            <span>Marketplace guide</span>
            <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
          </a>
        </div>

        {/* Filter Controls */}
        <div className="mt-8 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div
            role="group"
            aria-label="Filter catalog by category"
            className="obs-scroll flex gap-2 overflow-x-auto pb-1"
          >
            <button
              type="button"
              onClick={() => setSelectedCategory('All')}
              aria-pressed={selectedCategory === 'All'}
              className={`shrink-0 rounded-xl border px-3.5 py-2 font-mono text-xs font-semibold transition-colors ${
                selectedCategory === 'All'
                  ? 'border-indigo-400/55 bg-indigo-500/20 text-white'
                  : 'border-white/[0.08] bg-white/[0.03] text-slate-300 hover:border-white/20 hover:text-white'
              }`}
            >
              All ({totalCount})
            </button>
            {categories.map((cat) => (
              <button
                key={cat.name}
                type="button"
                onClick={() => setSelectedCategory(cat.name)}
                aria-pressed={selectedCategory === cat.name}
                className={`shrink-0 rounded-xl border px-3.5 py-2 font-mono text-xs font-medium transition-colors ${
                  selectedCategory === cat.name
                    ? 'border-indigo-400/55 bg-indigo-500/20 text-white'
                    : 'border-white/[0.08] bg-white/[0.03] text-slate-300 hover:border-white/20 hover:text-white'
                }`}
              >
                {cat.name} ({cat.count})
              </button>
            ))}
          </div>

          <div className="relative w-full lg:w-80">
            <label htmlFor="catalog-search" className="sr-only">
              Search 77 bare-metal packages
            </label>
            <Search
              className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
              aria-hidden="true"
            />
            <input
              id="catalog-search"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search app, service unit, or port..."
              className="w-full rounded-xl border border-white/12 bg-[#0a0f1c]/90 py-2.5 pl-10 pr-9 text-sm text-white placeholder:text-slate-500 focus:border-indigo-400/60 focus:outline-none focus:ring-2 focus:ring-indigo-400/40"
            />
            {query && (
              <button
                type="button"
                onClick={() => setQuery('')}
                aria-label="Clear catalog search"
                className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-md p-1 text-slate-400 hover:text-white"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Grouped Catalog Output */}
        {groupedByCategory.length === 0 ? (
          <div className="obs-glass mt-8 rounded-2xl p-10 text-center">
            <p className="text-sm text-slate-300">
              No packages match <span className="font-mono text-white">&ldquo;{query}&rdquo;</span>.
            </p>
            <button
              type="button"
              onClick={() => {
                setQuery('');
                setSelectedCategory('All');
              }}
              className="mt-3 rounded-lg border border-indigo-400/40 bg-indigo-500/15 px-3.5 py-1.5 text-xs font-semibold text-indigo-200 hover:bg-indigo-500/25"
            >
              Reset filters
            </button>
          </div>
        ) : (
          <div className="mt-8 space-y-10">
            {groupedByCategory.map(([categoryName, categoryApps]) => (
              <div key={categoryName}>
                <div className="mb-4 flex items-center justify-between border-b border-white/[0.08] pb-2.5">
                  <div className="flex items-center gap-2.5">
                    <h3 className="text-lg font-bold text-white">
                      {categoryName}
                    </h3>
                    <span
                      className={`rounded-full border px-2.5 py-0.5 font-mono text-[11px] font-semibold ${
                        CATEGORY_ACCENTS[categoryName] ??
                        'border-white/15 bg-white/[0.06] text-slate-200'
                      }`}
                    >
                      {categoryApps.length}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                  {categoryApps.map((app) => {
                    const isRetired = app.status === 'retired';
                    const isExperimental = app.description
                      .toLowerCase()
                      .startsWith('experimental');
                    return (
                      <article
                        key={app.name}
                        className="obs-glass flex flex-col justify-between rounded-xl p-3.5 transition-colors hover:border-indigo-400/35"
                      >
                        <div>
                          <div className="flex items-start justify-between gap-2">
                            <h4 className="text-sm font-bold text-white">
                              {app.label}
                            </h4>
                            <div className="flex shrink-0 items-center gap-1.5">
                              {isRetired && (
                                <span className="rounded border border-amber-400/35 bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber-200">
                                  Retired
                                </span>
                              )}
                              {isExperimental && (
                                <span className="rounded border border-fuchsia-400/35 bg-fuchsia-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-fuchsia-200">
                                  Exp
                                </span>
                              )}
                              <span className="rounded border border-white/10 bg-white/[0.04] px-1.5 py-0.5 font-mono text-[10px] text-slate-300 tabular-nums">
                                {app.default_port > 0
                                  ? `:${app.default_port}`
                                  : 'daemon'}
                              </span>
                            </div>
                          </div>
                          <p className="mt-2 line-clamp-2 text-xs leading-relaxed text-slate-400">
                            {app.description}
                          </p>
                        </div>
                        <div className="mt-3 flex items-center justify-between border-t border-white/[0.06] pt-2.5 font-mono text-[11px] text-slate-500">
                          <span className="truncate">{app.service_name}</span>
                          <span className="ml-2 shrink-0 text-slate-400">
                            systemd
                          </span>
                        </div>
                      </article>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
