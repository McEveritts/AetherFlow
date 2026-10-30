import { Activity } from 'lucide-react';
import { ProcessInfo } from '@/types/dashboard';
import { DataGrid } from '@/components/ui/DataGrid';
import { ColumnDef } from '@tanstack/react-table';
import { useMemo } from 'react';
import useSWR from 'swr';
import { useSystemStore } from '@/store/useSystemStore';

interface ProcessWidgetProps {
    processes: ProcessInfo[];
    density?: 'compact' | 'immersive';
}

export default function ProcessWidget({ processes, density = 'compact' }: ProcessWidgetProps) {
    const isImmersive = density === 'immersive';
    const { data: services } = useSWR<Record<string, { status: string; uptime: string; version: string; process?: string; id?: string }>>('/api/v1/auth/services');
    const setActiveTab = useSystemStore((state) => state.setActiveTab);

    const columns = useMemo<ColumnDef<ProcessInfo>[]>(() => [
        {
            accessorKey: 'pid',
            header: 'PID',
            cell: info => <span className="text-slate-500 font-mono text-xs tabular-nums">{info.getValue() as number}</span>,
            size: 72,
        },
        {
            accessorKey: 'name',
            header: 'Process',
            cell: info => {
                const name = info.getValue() as string;
                const normName = name.toLowerCase();

                let isService = false;
                if (services) {
                    isService = Object.entries(services).some(([serviceName, data]) => {
                        const procBase = (data.process || '').split('@')[0].replace(/\.service$/i, '').toLowerCase();
                        const procStem = procBase.replace(/-(web|nox|server|daemon)$/i, '');
                        const idLower = (data.id || '').toLowerCase();
                        const labelLower = serviceName.toLowerCase();
                        return (
                            procBase === normName ||
                            procStem === normName ||
                            idLower === normName ||
                            labelLower === normName ||
                            (normName.replace(/-(nox|server|daemon)$/i, '') === idLower && idLower.length > 0)
                        );
                    });
                }

                if (isService) {
                    return (
                        <button
                            onClick={() => setActiveTab('services')}
                            className="font-semibold text-emerald-400 hover:text-emerald-300 truncate block max-w-[180px] text-left hover:underline cursor-pointer transition-colors py-0.5 text-xs"
                            title={`Go to Service: ${name}`}
                        >
                            {name}
                        </button>
                    );
                }

                return <span className="font-medium text-slate-200 truncate block max-w-[180px] text-xs" title={name}>{name}</span>;
            },
        },
        {
            accessorKey: 'cpu',
            header: () => <div className="text-right w-full">CPU %</div>,
            cell: info => {
                const cpu = info.getValue() as number;
                return (
                    <div className="flex items-center justify-end gap-2">
                        <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className="h-full rounded-full transition-all duration-300"
                                style={{
                                    width: `${Math.min(cpu, 100)}%`,
                                    backgroundColor: cpu > 50 ? '#ef4444' : cpu > 20 ? '#f59e0b' : '#6366f1'
                                }}
                            />
                        </div>
                        <span className={`font-mono text-xs tabular-nums font-bold ${cpu > 50 ? 'text-rose-400' : cpu > 20 ? 'text-amber-400' : 'text-slate-200'}`}>
                            {cpu.toFixed(1)}
                        </span>
                    </div>
                );
            },
            size: 110,
        },
        {
            accessorKey: 'mem',
            header: () => <div className="text-right w-full">MEM %</div>,
            cell: info => {
                const mem = info.getValue() as number;
                return (
                    <div className="flex items-center justify-end gap-2">
                        <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-purple-500 rounded-full transition-all duration-300"
                                style={{ width: `${Math.min(mem, 100)}%` }}
                            />
                        </div>
                        <span className="font-mono text-xs tabular-nums text-slate-400">{mem.toFixed(1)}</span>
                    </div>
                );
            },
            size: 110,
        }
    ], [services, setActiveTab]);

    return (
        <div className={`rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl relative overflow-hidden flex flex-col h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            {/* Header */}
            <div className="flex items-center justify-between pb-3 mb-3.5 border-b border-white/[0.06] shrink-0">
                <div className="flex items-center gap-2.5">
                    <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shrink-0">
                        <Activity size={16} />
                    </div>
                    <div>
                        <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Top Processes</h2>
                        <p className="text-[11px] text-slate-500 mt-1">Active kernel tasks ordered by CPU load</p>
                    </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-lg">
                    {(processes || []).length} Tasks
                </span>
            </div>

            {/* Table */}
            <div className="flex-1 overflow-hidden rounded-xl border border-white/[0.04] bg-black/20">
                <DataGrid
                    columns={columns}
                    data={processes || []}
                    className="h-full !max-h-full border-none shadow-none rounded-xl"
                    rowHeight={isImmersive ? 48 : 42}
                />
            </div>
        </div>
    );
}
