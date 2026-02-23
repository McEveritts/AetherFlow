import { Cpu } from 'lucide-react';
import { SystemMetrics, HardwareReport } from '@/types/dashboard';

interface CpuWidgetProps {
    metrics: SystemMetrics;
    hardware: HardwareReport | null;
}

export default function CpuWidget({ metrics, hardware }: CpuWidgetProps) {
    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl">
            <div className="flex items-center justify-between mb-6">
                <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                    <Cpu size={18} className="text-blue-400" /> CPU Allocation
                </h2>
                <span className="text-xs font-medium px-2.5 py-1 bg-white/5 rounded-full text-slate-400 max-w-[200px] truncate" title={hardware?.cpu?.model || 'Unknown CPU'}>
                    {hardware?.cpu?.model || 'Unknown CPU'}
                </span>
            </div>

            <div className="flex flex-col items-center justify-center py-4 relative">
                {/* Mock Circle Graph */}
                <div className="w-32 h-32 rounded-full border-[12px] border-slate-800 relative flex items-center justify-center">
                    <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="44" stroke="currentColor" strokeWidth="12" fill="none" className="text-blue-500" strokeDasharray={`${metrics.cpu_usage * 2.76} 276`} strokeLinecap="round" />
                    </svg>
                    <div className="text-center absolute">
                        <span className="text-3xl font-bold tracking-tighter text-slate-100">{metrics.cpu_usage.toFixed(1)}</span>
                        <span className="text-sm text-slate-400 block">%</span>
                    </div>
                </div>
            </div>

            {/* Decorative background glow */}
            <div className="absolute -bottom-16 -right-16 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>
        </div>
    );
}
