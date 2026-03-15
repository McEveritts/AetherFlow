'use client';

import { useMemo, useId } from 'react';
import { AreaChart, Area, ResponsiveContainer, Tooltip as RechartsTooltip } from 'recharts';

interface SparklineProps {
    data: number[];
    color?: string;
    gradientFrom?: string;
    gradientTo?: string;
    height?: number;
    width?: number; // Kept for compatibility, but ignored in ResponsiveContainer
    strokeWidth?: number;
    showArea?: boolean;
    className?: string;
    // Dual-line overlay mode
    data2?: number[];
    color2?: string;
    gradientFrom2?: string;
    gradientTo2?: string;
    label?: string;
    label2?: string;
    currentValue?: string;
    currentValue2?: string;
}

export default function Sparkline({
    data,
    color = '#6366f1',
    gradientFrom,
    gradientTo,
    height = 80,
    strokeWidth = 2,
    showArea = true,
    className = '',
    data2,
    color2 = '#10b981',
    gradientFrom2,
    gradientTo2,
    label,
    label2,
    currentValue,
    currentValue2,
}: SparklineProps) {
    const rawId = useId();
    const id = useMemo(() => rawId.replace(/:/g, ''), [rawId]);
    
    // Convert array of numbers to array of objects for Recharts
    const chartData = useMemo(() => {
        if (!data || data.length === 0) return [{ name: 'P0', val1: 0, val2: 0 }];
        return data.map((val, i) => ({
            name: `P${i}`,
            val1: val,
            val2: data2 ? data2[i] : undefined,
        }));
    }, [data, data2]);

    const gFrom = gradientFrom || color;
    const gTo = gradientTo || 'transparent';
    const gFrom2 = gradientFrom2 || color2;
    const gTo2 = gradientTo2 || 'transparent';

    return (
        <div className={`relative ${className}`} style={{ height: height + (label || label2 ? 24 : 0) }}>
            {(label || label2) && (
                <div className="flex items-center gap-4 mb-2 px-2 z-10 relative pointer-events-none">
                    {label && (
                        <div className="flex items-center gap-1.5">
                            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                            <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">{label}</span>
                            {currentValue && <span className="text-xs font-bold text-slate-200 ml-1">{currentValue}</span>}
                        </div>
                    )}
                    {label2 && (
                        <div className="flex items-center gap-1.5">
                            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color2 }} />
                            <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">{label2}</span>
                            {currentValue2 && <span className="text-xs font-bold text-slate-200 ml-1">{currentValue2}</span>}
                        </div>
                    )}
                </div>
            )}
            <div style={{ height: height }} className="w-full">
                <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData} margin={{ top: 5, right: 0, left: 0, bottom: 0 }}>
                        <defs>
                            <linearGradient id={`${id}-g1`} x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor={gFrom} stopOpacity={0.3} />
                                <stop offset="95%" stopColor={gTo} stopOpacity={0} />
                            </linearGradient>
                            {data2 && (
                                <linearGradient id={`${id}-g2`} x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor={gFrom2} stopOpacity={0.3} />
                                    <stop offset="95%" stopColor={gTo2} stopOpacity={0} />
                                </linearGradient>
                            )}
                        </defs>
                        
                        <RechartsTooltip 
                            contentStyle={{ 
                                backgroundColor: 'rgba(15, 23, 42, 0.9)', 
                                border: '1px solid rgba(255,255,255,0.1)',
                                borderRadius: '12px',
                                boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5)',
                                backdropFilter: 'blur(16px)'
                            }}
                            itemStyle={{ color: '#f8fafc', fontSize: '12px', fontWeight: 'bold' }}
                            labelStyle={{ display: 'none' }}
                            cursor={{ stroke: 'rgba(255,255,255,0.1)', strokeWidth: 1, strokeDasharray: '4 4' }}
                            animationDuration={200}
                        />

                        {data2 && (
                            <Area 
                                type="monotone" 
                                dataKey="val2" 
                                stroke={color2} 
                                strokeWidth={strokeWidth}
                                fillOpacity={1} 
                                fill={showArea ? `url(#${id}-g2)` : "none"} 
                                isAnimationActive={true}
                                animationDuration={500}
                                name={label2 || 'Metric 2'}
                            />
                        )}
                        <Area 
                            type="monotone" 
                            dataKey="val1" 
                            stroke={color} 
                            strokeWidth={strokeWidth}
                            fillOpacity={1} 
                            fill={showArea ? `url(#${id}-g1)` : "none"} 
                            isAnimationActive={true}
                            animationDuration={500}
                            name={label || 'Metric 1'}
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}
