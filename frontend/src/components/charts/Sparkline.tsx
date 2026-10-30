'use client';

import React, { useMemo, useId, useState, useCallback } from 'react';
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

interface ChartDataPoint {
    name: string;
    val1: number;
    val2?: number;
}

const CHART_MARGIN = { top: 5, right: 0, left: 0, bottom: 0 };

const TOOLTIP_CONTENT_STYLE: React.CSSProperties = {
    backgroundColor: 'rgba(15, 23, 42, 0.9)',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: '12px',
    boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5)',
    backdropFilter: 'blur(16px)',
};

const TOOLTIP_ITEM_STYLE: React.CSSProperties = {
    color: '#f8fafc',
    fontSize: '12px',
    fontWeight: 'bold',
};

const TOOLTIP_LABEL_STYLE: React.CSSProperties = {
    display: 'none',
};

const TOOLTIP_CURSOR = {
    stroke: 'rgba(255,255,255,0.15)',
    strokeWidth: 1,
    strokeDasharray: '4 4',
};

function roundTwo(val: number): number {
    if (!Number.isFinite(val)) return 0;
    return Number(val.toFixed(2));
}

function formatTooltipValue(
    value: number | string | ReadonlyArray<number | string> | undefined,
    name: number | string | undefined
): [string, string] {
    const raw = Array.isArray(value) ? value[0] : value;
    const num = typeof raw === 'number' ? raw : Number(raw ?? 0);
    const formatted = Number.isFinite(num) ? String(roundTwo(num)) : '0';
    return [formatted, String(name ?? '')];
}

interface MemoizedSparklineChartProps {
    chartData: ChartDataPoint[];
    id: string;
    color: string;
    color2: string;
    gFrom: string;
    gTo: string;
    gFrom2: string;
    gTo2: string;
    strokeWidth: number;
    showArea: boolean;
    hasData2: boolean;
    label?: string;
    label2?: string;
}

const MemoizedSparklineChart = React.memo(function MemoizedSparklineChart({
    chartData,
    id,
    color,
    color2,
    gFrom,
    gTo,
    gFrom2,
    gTo2,
    strokeWidth,
    showArea,
    hasData2,
    label,
    label2,
}: MemoizedSparklineChartProps) {
    return (
        <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={CHART_MARGIN}>
                <defs>
                    <linearGradient id={`${id}-g1`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={gFrom} stopOpacity={0.3} />
                        <stop offset="95%" stopColor={gTo} stopOpacity={0} />
                    </linearGradient>
                    {hasData2 && (
                        <linearGradient id={`${id}-g2`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={gFrom2} stopOpacity={0.3} />
                            <stop offset="95%" stopColor={gTo2} stopOpacity={0} />
                        </linearGradient>
                    )}
                </defs>

                <RechartsTooltip
                    contentStyle={TOOLTIP_CONTENT_STYLE}
                    itemStyle={TOOLTIP_ITEM_STYLE}
                    labelStyle={TOOLTIP_LABEL_STYLE}
                    cursor={TOOLTIP_CURSOR}
                    formatter={formatTooltipValue}
                    animationDuration={120}
                />

                {hasData2 && (
                    <Area
                        type="monotone"
                        dataKey="val2"
                        stroke={color2}
                        strokeWidth={strokeWidth}
                        fillOpacity={1}
                        fill={showArea ? `url(#${id}-g2)` : 'none'}
                        isAnimationActive={false}
                        name={label2 || 'Metric 2'}
                    />
                )}
                <Area
                    type="monotone"
                    dataKey="val1"
                    stroke={color}
                    strokeWidth={strokeWidth}
                    fillOpacity={1}
                    fill={showArea ? `url(#${id}-g1)` : 'none'}
                    isAnimationActive={false}
                    name={label || 'Metric 1'}
                />
            </AreaChart>
        </ResponsiveContainer>
    );
});

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
    const [frozenChartData, setFrozenChartData] = useState<ChartDataPoint[] | null>(null);

    // Convert array of numbers to array of objects for Recharts, capped at 0.XX precision
    const liveChartData = useMemo<ChartDataPoint[]>(() => {
        if (!data || data.length === 0) {
            return [
                { name: 'P0', val1: 0, val2: 0 },
                { name: 'P1', val1: 0, val2: 0 },
            ];
        }
        const normalized = data.length === 1 ? [data[0], data[0]] : data;
        const normalized2 = data2 ? (data2.length === 1 ? [data2[0], data2[0]] : data2) : undefined;
        return normalized.map((val, i) => ({
            name: `P${i}`,
            val1: roundTwo(val),
            val2: normalized2 && normalized2[i] !== undefined ? roundTwo(normalized2[i]) : undefined,
        }));
    }, [data, data2]);

    const activeChartData = frozenChartData ?? liveChartData;

    const handleMouseEnter = useCallback(() => {
        setFrozenChartData((prev) => prev ?? liveChartData);
    }, [liveChartData]);

    const handleMouseLeave = useCallback(() => {
        setFrozenChartData(null);
    }, []);

    const gFrom = gradientFrom || color;
    const gTo = gradientTo || 'transparent';
    const gFrom2 = gradientFrom2 || color2;
    const gTo2 = gradientTo2 || 'transparent';

    return (
        <div
            className={`relative select-none ${className}`}
            style={{ height: height + (label || label2 ? 24 : 0), touchAction: 'pan-y' }}
            onMouseEnter={handleMouseEnter}
            onMouseLeave={handleMouseLeave}
            onTouchStart={handleMouseEnter}
            onTouchEnd={handleMouseLeave}
            onTouchCancel={handleMouseLeave}
        >
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
            <div style={{ height: height, touchAction: 'pan-y' }} className="w-full">
                <MemoizedSparklineChart
                    chartData={activeChartData}
                    id={id}
                    color={color}
                    color2={color2}
                    gFrom={gFrom}
                    gTo={gTo}
                    gFrom2={gFrom2}
                    gTo2={gTo2}
                    strokeWidth={strokeWidth}
                    showArea={showArea}
                    hasData2={Boolean(data2)}
                    label={label}
                    label2={label2}
                />
            </div>
        </div>
    );
}
