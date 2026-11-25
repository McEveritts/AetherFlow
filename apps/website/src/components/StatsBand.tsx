import { statsByTheNumbers, type AccentTone } from '@/content/home';

const TONE_VALUE_STYLES: Record<AccentTone, string> = {
  indigo: 'text-indigo-300',
  violet: 'text-violet-300',
  cyan: 'text-cyan-300',
  fuchsia: 'text-fuchsia-300',
  emerald: 'text-emerald-300',
  amber: 'text-amber-300',
};

const TONE_DOT_STYLES: Record<AccentTone, string> = {
  indigo: 'bg-indigo-400 shadow-[0_0_10px_rgba(99,102,241,0.7)]',
  violet: 'bg-violet-400 shadow-[0_0_10px_rgba(139,92,246,0.7)]',
  cyan: 'bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.7)]',
  fuchsia: 'bg-fuchsia-400 shadow-[0_0_10px_rgba(217,70,239,0.7)]',
  emerald: 'bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.7)]',
  amber: 'bg-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.7)]',
};

export function StatsBand() {
  return (
    <section
      aria-labelledby="stats-heading"
      className="border-y border-white/[0.07] bg-white/[0.015] py-14 sm:py-16"
    >
      <div className="mx-auto max-w-[1440px] px-4 sm:px-6 lg:px-10">
        <div className="mb-8 flex flex-col justify-between gap-2 sm:flex-row sm:items-end">
          <div>
            <p className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
              v4.0.0 by the Numbers
            </p>
            <h2
              id="stats-heading"
              className="mt-1.5 text-2xl font-bold tracking-tight text-white sm:text-3xl"
            >
              Verified architecture metrics from HEAD
            </h2>
          </div>
          <p className="max-w-md text-sm text-slate-400">
            Every count maps directly to workspace crates, catalog manifests, and git history since v3.2.7.
          </p>
        </div>

        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          {statsByTheNumbers.map((stat) => (
            <div
              key={stat.label}
              className="obs-glass flex flex-col justify-between rounded-2xl p-5 transition-colors hover:border-indigo-400/35"
            >
              <div className="flex items-center justify-between gap-2">
                <dt className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  {stat.label}
                </dt>
                <span
                  className={`h-2 w-2 shrink-0 rounded-full ${TONE_DOT_STYLES[stat.tone]}`}
                  aria-hidden="true"
                />
              </div>
              <dd
                className={`mt-3 font-mono text-4xl font-extrabold tracking-tight tabular-nums ${TONE_VALUE_STYLES[stat.tone]}`}
              >
                {stat.value}
              </dd>
              <p className="mt-2.5 text-xs leading-relaxed text-slate-400">
                {stat.detail}
              </p>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}
