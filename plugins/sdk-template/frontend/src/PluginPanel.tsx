import { useEffect, useState } from 'react';
import { getSystemMetrics } from './lib/aetherflow';

interface Snapshot {
    cpu_usage?: number;
    uptime?: string;
}

export function PluginPanel() {
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
    const [error, setError] = useState<string>('');

    useEffect(() => {
        let cancelled = false;

        getSystemMetrics()
            .then((data) => {
                if (!cancelled) {
                    setSnapshot(data);
                }
            })
            .catch((err: unknown) => {
                if (!cancelled) {
                    setError(err instanceof Error ? err.message : 'Failed to load plugin data');
                }
            });

        return () => {
            cancelled = true;
        };
    }, []);

    return (
        <section className="rounded-2xl border border-white/10 bg-slate-950/80 p-6 text-slate-100">
            <div className="flex items-center justify-between gap-4">
                <div>
                    <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Plugin</p>
                    <h3 className="mt-2 text-xl font-semibold">{{PLUGIN_NAME}}</h3>
                </div>
                <span className="rounded-full border border-cyan-400/20 bg-cyan-500/10 px-3 py-1 text-xs uppercase tracking-[0.2em] text-cyan-300">
                    SDK Demo
                </span>
            </div>

            {error && <p className="mt-4 text-sm text-rose-300">{error}</p>}

            {snapshot && (
                <div className="mt-6 grid gap-4 md:grid-cols-2">
                    <div className="rounded-xl border border-white/5 bg-white/5 p-4">
                        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">CPU</p>
                        <p className="mt-2 text-2xl font-semibold">{snapshot.cpu_usage ?? 0}%</p>
                    </div>
                    <div className="rounded-xl border border-white/5 bg-white/5 p-4">
                        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Uptime</p>
                        <p className="mt-2 text-2xl font-semibold">{snapshot.uptime ?? '-'}</p>
                    </div>
                </div>
            )}
        </section>
    );
}
