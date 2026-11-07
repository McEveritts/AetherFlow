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

    const sortedProcesses = useMemo(() => {
        if (!processes || processes.length === 0) {
            return [];
        }
        const indexedProcesses = processes.map((processItem, originalIndex) => ({
            processItem,
            originalIndex,
        }));

        indexedProcesses.sort((firstEntry, secondEntry) => {
            const firstCpu = firstEntry.processItem.cpu;
            const secondCpu = secondEntry.processItem.cpu;
            const isFirstValid = typeof firstCpu === 'number' && Number.isFinite(firstCpu);
            const isSecondValid = typeof secondCpu === 'number' && Number.isFinite(secondCpu);

            if (isFirstValid && isSecondValid) {
                if (secondCpu !== firstCpu) {
                    return secondCpu - firstCpu;
                }
                return firstEntry.originalIndex - secondEntry.originalIndex;
            }
            if (isFirstValid && !isSecondValid) {
                return -1;
            }
            if (!isFirstValid && isSecondValid) {
                return 1;
            }
            return firstEntry.originalIndex - secondEntry.originalIndex;
        });

        return indexedProcesses.map((entry) => entry.processItem);
    }, [processes]);

    const columns = useMemo<ColumnDef<ProcessInfo>[]>(() => [
        {
            accessorKey: 'pid',
            header: 'PID',
            cell: cellInformation => <span className="text-slate-300 font-mono text-[13px] tabular-nums font-medium">{cellInformation.getValue() as number}</span>,
            size: 72,
        },
        {
            accessorKey: 'name',
            header: 'Process',
            cell: cellInformation => {
                const processName = cellInformation.getValue() as string;
                const normalizedProcessName = processName.toLowerCase();

                let isAssociatedService = false;
                if (services) {
                    isAssociatedService = Object.entries(services).some(([serviceName, serviceData]) => {
                        const processBase = (serviceData.process || '').split('@')[0].replace(/\.service$/i, '').toLowerCase();
                        const processStem = processBase.replace(/-(web|nox|server|daemon)$/i, '');
                        const identifierLower = (serviceData.id || '').toLowerCase();
                        const labelLower = serviceName.toLowerCase();
                        return (
                            processBase === normalizedProcessName ||
                            processStem === normalizedProcessName ||
                            identifierLower === normalizedProcessName ||
                            labelLower === normalizedProcessName ||
                            (normalizedProcessName.replace(/-(nox|server|daemon)$/i, '') === identifierLower && identifierLower.length > 0)
                        );
                    });
                }

                if (isAssociatedService) {
                    return (
                        <button
                            type="button"
                            onClick={() => setActiveTab('services')}
                            className="font-semibold text-emerald-300 hover:text-emerald-200 truncate block max-w-[180px] text-left hover:underline cursor-pointer transition-colors py-1 text-[13px] focus-visible:ring-2 focus-visible:ring-emerald-500 rounded"
                            title={`Inspect Service: ${processName}`}
                        >
                            {processName}
                        </button>
                    );
                }

                return <span className="font-medium text-slate-200 truncate block max-w-[180px] text-[13px]" title={processName}>{processName}</span>;
            },
        },
        {
            accessorKey: 'cpu',
            header: () => (
                <div className="text-right w-full text-xs font-semibold text-slate-300 flex items-center justify-end gap-1">
                    <span>CPU %</span>
                    <span className="text-indigo-400 font-bold">↓</span>
                </div>
            ),
            cell: cellInformation => {
                const processCpu = cellInformation.getValue() as number;
                const formattedCpu = typeof processCpu === 'number' && Number.isFinite(processCpu)
                    ? `${processCpu.toFixed(1)}%`
                    : '0.0%';
                return (
                    <div className="text-right w-full">
                        <span className={`font-mono text-[13px] tabular-nums font-bold ${
                            processCpu > 50 ? 'text-rose-400' : processCpu > 20 ? 'text-amber-400' : 'text-slate-200'
                        }`}>
                            {formattedCpu}
                        </span>
                    </div>
                );
            },
            size: 90,
        },
        {
            accessorKey: 'mem',
            header: () => <div className="text-right w-full text-xs font-semibold text-slate-300">MEM %</div>,
            cell: cellInformation => {
                const processMemory = cellInformation.getValue() as number;
                const formattedMemory = typeof processMemory === 'number' && Number.isFinite(processMemory)
                    ? `${processMemory.toFixed(1)}%`
                    : '0.0%';
                return (
                    <div className="text-right w-full">
                        <span className="font-mono text-[13px] tabular-nums text-slate-200 font-semibold">
                            {formattedMemory}
                        </span>
                    </div>
                );
            },
            size: 90,
        }
    ], [services, setActiveTab]);

    return (
        <div className={`rounded-2xl border border-slate-800/80 bg-slate-900/85 backdrop-blur-xl relative overflow-hidden flex flex-col h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div className="flex items-center justify-between pb-3 mb-3.5 border-b border-slate-800/80 shrink-0">
                <div className="flex items-center gap-2.5">
                    <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shrink-0">
                        <Activity size={16} />
                    </div>
                    <div>
                        <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">Top Processes</h2>
                        <p className="text-xs text-slate-400 mt-1">Active kernel tasks ordered by CPU load</p>
                    </div>
                </div>
                <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider bg-slate-800/60 border border-slate-700/60 px-2.5 py-1 rounded-lg">
                    {sortedProcesses.length} Tasks
                </span>
            </div>

            <div className="flex-1 overflow-hidden rounded-xl border border-slate-800/60 bg-slate-950/60">
                <DataGrid
                    columns={columns}
                    data={sortedProcesses}
                    className="h-full !max-h-full border-none shadow-none rounded-xl"
                    rowHeight={isImmersive ? 48 : 42}
                />
            </div>
        </div>
    );
}
