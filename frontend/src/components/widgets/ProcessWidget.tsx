import { Activity } from 'lucide-react';
import { ProcessInfo } from '@/types/dashboard';

interface ProcessWidgetProps {
    processes: ProcessInfo[];
}

export default function ProcessWidget({ processes }: ProcessWidgetProps) {
    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden backdrop-blur-xl">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <Activity size={16} className="text-cyan-400" /> Top Processes
                </h2>
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">By CPU</span>
            </div>

            {/* Table */}
            <div className="overflow-hidden rounded-xl border border-white/[0.03]">
                <table className="w-full text-xs">
                    <thead>
                        <tr className="bg-slate-900/80">
                            <th className="text-left py-2 px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider">PID</th>
                            <th className="text-left py-2 px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider">Process</th>
                            <th className="text-right py-2 px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider w-24">CPU %</th>
                            <th className="text-right py-2 px-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider w-24">MEM %</th>
                        </tr>
                    </thead>
                    <tbody>
                        {(processes || []).map((proc, i) => (
                            <tr key={proc.pid} className={`border-t border-white/[0.03] ${i % 2 === 0 ? 'bg-white/[0.01]' : ''} hover:bg-white/[0.04] transition-colors`}>
                                <td className="py-2 px-3 text-slate-500 font-mono tabular-nums">{proc.pid}</td>
                                <td className="py-2 px-3 text-slate-200 font-medium truncate max-w-[180px]" title={proc.name}>{proc.name}</td>
                                <td className="py-2 px-3 text-right">
                                    <div className="flex items-center justify-end gap-2">
                                        <div className="w-14 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                            <div
                                                className="h-full rounded-full transition-all duration-300"
                                                style={{
                                                    width: `${Math.min(proc.cpu, 100)}%`,
                                                    backgroundColor: proc.cpu > 50 ? '#ef4444' : proc.cpu > 20 ? '#f59e0b' : '#6366f1'
                                                }}
                                            />
                                        </div>
                                        <span className={`font-mono tabular-nums font-bold ${proc.cpu > 50 ? 'text-red-400' : proc.cpu > 20 ? 'text-amber-400' : 'text-slate-300'}`}>
                                            {proc.cpu.toFixed(1)}
                                        </span>
                                    </div>
                                </td>
                                <td className="py-2 px-3 text-right">
                                    <div className="flex items-center justify-end gap-2">
                                        <div className="w-14 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                            <div
                                                className="h-full bg-purple-500 rounded-full transition-all duration-300"
                                                style={{ width: `${Math.min(proc.mem, 100)}%` }}
                                            />
                                        </div>
                                        <span className="font-mono tabular-nums text-slate-400">{proc.mem.toFixed(1)}</span>
                                    </div>
                                </td>
                            </tr>
                        ))}
                        {(!processes || processes.length === 0) && (
                            <tr>
                                <td colSpan={4} className="py-6 text-center text-slate-500">No process data available</td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
