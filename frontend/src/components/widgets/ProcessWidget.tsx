import { Activity } from 'lucide-react';
import { ProcessInfo } from '@/types/dashboard';
import { DataGrid } from '@/components/ui/DataGrid';
import { ColumnDef } from '@tanstack/react-table';
import { useMemo } from 'react';

interface ProcessWidgetProps {
    processes: ProcessInfo[];
}

export default function ProcessWidget({ processes }: ProcessWidgetProps) {
    const columns = useMemo<ColumnDef<ProcessInfo>[]>(() => [
        {
            accessorKey: 'pid',
            header: 'PID',
            cell: info => <span className="text-slate-500 font-mono tabular-nums">{info.getValue() as number}</span>,
            size: 80,
        },
        {
            accessorKey: 'name',
            header: 'Process',
            cell: info => <span className="font-medium text-slate-200 truncate block max-w-[180px]" title={info.getValue() as string}>{info.getValue() as string}</span>,
        },
        {
            accessorKey: 'cpu',
            header: () => <div className="text-right w-full">CPU %</div>,
            cell: info => {
                const cpu = info.getValue() as number;
                return (
                    <div className="flex items-center justify-end gap-2">
                        <div className="w-14 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className="h-full rounded-full transition-all duration-300"
                                style={{
                                    width: `${Math.min(cpu, 100)}%`,
                                    backgroundColor: cpu > 50 ? '#ef4444' : cpu > 20 ? '#f59e0b' : '#6366f1'
                                }}
                            />
                        </div>
                        <span className={`font-mono tabular-nums font-bold ${cpu > 50 ? 'text-red-400' : cpu > 20 ? 'text-amber-400' : 'text-slate-300'}`}>
                            {cpu.toFixed(1)}
                        </span>
                    </div>
                );
            },
            size: 120,
        },
        {
            accessorKey: 'mem',
            header: () => <div className="text-right w-full">MEM %</div>,
            cell: info => {
                const mem = info.getValue() as number;
                return (
                    <div className="flex items-center justify-end gap-2">
                        <div className="w-14 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-purple-500 rounded-full transition-all duration-300"
                                style={{ width: `${Math.min(mem, 100)}%` }}
                            />
                        </div>
                        <span className="font-mono tabular-nums text-slate-400">{mem.toFixed(1)}</span>
                    </div>
                );
            },
            size: 120,
        }
    ], []);

    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden backdrop-blur-xl flex flex-col h-full">
            {/* Header */}
            <div className="flex items-center justify-between mb-4 shrink-0">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <Activity size={16} className="text-cyan-400" /> Top Processes
                </h2>
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">By CPU</span>
            </div>

            {/* Table */}
            <div className="flex-1 overflow-hidden">
                <DataGrid
                    columns={columns}
                    data={processes || []}
                    className="h-full !max-h-full border-none shadow-none rounded-xl"
                    rowHeight={48}
                />
            </div>
        </div>
    );
}
