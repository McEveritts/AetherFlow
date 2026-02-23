'use client';

import { useMemo } from 'react';

interface SparklineProps {
    data: number[];
    color?: string;
    gradientFrom?: string;
    gradientTo?: string;
    height?: number;
    width?: number;
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

function buildPath(data: number[], width: number, height: number, padding: number): string {
    if (data.length < 2) return '';
    const maxVal = Math.max(...data, 1);
    const step = width / (data.length - 1);

    return data.map((val, i) => {
        const x = i * step;
        const y = height - padding - ((val / maxVal) * (height - padding * 2));
        return `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`;
    }).join(' ');
}

function buildAreaPath(data: number[], width: number, height: number, padding: number): string {
    if (data.length < 2) return '';
    const linePath = buildPath(data, width, height, padding);
    const step = width / (data.length - 1);
    const lastX = (data.length - 1) * step;
    return `${linePath} L${lastX.toFixed(2)},${(height - padding).toFixed(2)} L0,${(height - padding).toFixed(2)} Z`;
}

export default function Sparkline({
    data,
    color = '#6366f1',
    gradientFrom,
    gradientTo,
    height = 80,
    width = 300,
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
    const id = useMemo(() => `spark-${Math.random().toString(36).slice(2, 9)}`, []);
    const padding = 4;

    const path1 = useMemo(() => buildPath(data, width, height, padding), [data, width, height]);
    const area1 = useMemo(() => showArea ? buildAreaPath(data, width, height, padding) : '', [data, width, height, showArea]);
    const path2 = useMemo(() => data2 ? buildPath(data2, width, height, padding) : '', [data2, width, height]);
    const area2 = useMemo(() => data2 && showArea ? buildAreaPath(data2, width, height, padding) : '', [data2, width, height, showArea]);

    const gFrom = gradientFrom || color;
    const gTo = gradientTo || 'transparent';
    const gFrom2 = gradientFrom2 || color2;
    const gTo2 = gradientTo2 || 'transparent';

    return (
        <div className={`relative ${className}`}>
            {(label || label2) && (
                <div className="flex items-center gap-4 mb-2 px-1">
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
            <svg
                viewBox={`0 0 ${width} ${height}`}
                preserveAspectRatio="none"
                className="w-full"
                style={{ height }}
            >
                <defs>
                    <linearGradient id={`${id}-g1`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={gFrom} stopOpacity="0.3" />
                        <stop offset="100%" stopColor={gTo} stopOpacity="0" />
                    </linearGradient>
                    {data2 && (
                        <linearGradient id={`${id}-g2`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={gFrom2} stopOpacity="0.3" />
                            <stop offset="100%" stopColor={gTo2} stopOpacity="0" />
                        </linearGradient>
                    )}
                </defs>
                {/* Grid lines */}
                {[0.25, 0.5, 0.75].map(pct => (
                    <line
                        key={pct}
                        x1="0"
                        y1={height * pct}
                        x2={width}
                        y2={height * pct}
                        stroke="rgba(255,255,255,0.04)"
                        strokeWidth="1"
                    />
                ))}
                {/* Area fills */}
                {showArea && area1 && <path d={area1} fill={`url(#${id}-g1)`} />}
                {showArea && area2 && <path d={area2} fill={`url(#${id}-g2)`} />}
                {/* Lines */}
                {path1 && <path d={path1} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />}
                {path2 && <path d={path2} fill="none" stroke={color2} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />}
            </svg>
        </div>
    );
}
