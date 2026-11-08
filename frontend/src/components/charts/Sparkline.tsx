'use client';

import React, { useMemo, useId, useState, useCallback } from 'react';
import { AreaChart, Area, ResponsiveContainer, Tooltip as RechartsTooltip, YAxis, XAxis } from 'recharts';

export interface SparklineProps {
    data: number[];
    color?: string;
    gradientFrom?: string;
    gradientTo?: string;
    height?: number;
    width?: number;
    strokeWidth?: number;
    showArea?: boolean;
    className?: string;
    data2?: number[];
    color2?: string;
    gradientFrom2?: string;
    gradientTo2?: string;
    label?: string;
    label2?: string;
    currentValue?: string;
    currentValue2?: string;
    isPercentage?: boolean;
    yDomain?: [number, number];
    showMagnitudeReferences?: boolean;
    unit?: string;
    timeContext?: string;
    timestamps?: number[];
    selectedWindow?: string;
    interpolation?: 'linear' | 'monotone';
    hasSharedSummary?: boolean;
    variant?: 'default' | 'mini';
}

export interface ChartDataPoint {
    name: string;
    index: number;
    val1?: number;
    val2?: number;
    timestamp?: number;
    timeLabel?: string;
}

export interface TimestampsValidationResult {
    isValid: boolean;
    startTimestamp?: number;
    endTimestamp?: number;
    spanSeconds?: number;
}

export function validateTimestampsAlignment(
    sampleCount: number,
    timestamps?: number[]
): TimestampsValidationResult {
    if (!timestamps || timestamps.length === 0 || sampleCount === 0 || timestamps.length !== sampleCount) {
        return { isValid: false };
    }
    for (let index = 0; index < timestamps.length; index++) {
        const currentTimestamp = timestamps[index];
        if (typeof currentTimestamp !== 'number' || !Number.isFinite(currentTimestamp) || currentTimestamp <= 0) {
            return { isValid: false };
        }
        if (index > 0 && currentTimestamp < timestamps[index - 1]) {
            return { isValid: false };
        }
    }
    const startTimestamp = timestamps[0];
    const endTimestamp = timestamps[timestamps.length - 1];
    const spanSeconds = Math.max(0, Math.round((endTimestamp - startTimestamp) / 1000));
    return {
        isValid: true,
        startTimestamp,
        endTimestamp,
        spanSeconds,
    };
}

export function computeEffectiveXDomain(
    sampleCount: number,
    alignment: TimestampsValidationResult
): [number, number] {
    if (alignment.isValid && alignment.startTimestamp !== undefined && alignment.endTimestamp !== undefined) {
        if (sampleCount === 1 || alignment.startTimestamp === alignment.endTimestamp) {
            return [alignment.startTimestamp - 1000, alignment.endTimestamp + 1000];
        }
        return [alignment.startTimestamp, alignment.endTimestamp];
    }
    if (sampleCount <= 1) {
        return [0, 1];
    }
    return [0, sampleCount - 1];
}

export function formatTimeEndpoint(timestampMs: number): string {
    if (!Number.isFinite(timestampMs) || timestampMs <= 0) return '';
    const dateObject = new Date(timestampMs);
    const formattedHours = String(dateObject.getUTCHours()).padStart(2, '0');
    const formattedMinutes = String(dateObject.getUTCMinutes()).padStart(2, '0');
    const formattedSeconds = String(dateObject.getUTCSeconds()).padStart(2, '0');
    return `${formattedHours}:${formattedMinutes}:${formattedSeconds} UTC`;
}

export function formatDurationSpan(secondsCount: number): string {
    if (secondsCount < 60) return `${secondsCount}s`;
    const spanMinutes = Math.floor(secondsCount / 60);
    const remainingSeconds = secondsCount % 60;
    if (remainingSeconds === 0) return `${spanMinutes}m`;
    return `${spanMinutes}m ${remainingSeconds}s`;
}

export function computeTimeContext({
    sampleCount,
    timestamps,
    selectedWindow,
    explicitTimeContext,
}: {
    sampleCount: number;
    timestamps?: number[];
    selectedWindow?: string;
    explicitTimeContext?: string;
}): string {
    if (explicitTimeContext) return explicitTimeContext;
    if (sampleCount === 0) {
        return selectedWindow ? `0 samples (${selectedWindow} max)` : '0 samples';
    }
    const alignment = validateTimestampsAlignment(sampleCount, timestamps);
    if (!alignment.isValid || !timestamps) {
        return `${sampleCount} sample${sampleCount === 1 ? '' : 's'} (sample sequence)`;
    }
    if (sampleCount === 1) {
        const singleTime = formatTimeEndpoint(timestamps[0]);
        const windowSuffix = selectedWindow ? ` · ${selectedWindow} max` : '';
        return `1 sample (${singleTime}${windowSuffix})`;
    }
    const spanString = formatDurationSpan(alignment.spanSeconds ?? 0);
    if (selectedWindow) {
        return `${sampleCount} samples (${spanString} span of ${selectedWindow} max)`;
    }
    return `${sampleCount} samples (${spanString} span)`;
}

const CHART_MARGIN = { top: 5, right: 6, left: 6, bottom: 5 };

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

export function roundTwo(numericValue: number): number {
    if (!Number.isFinite(numericValue)) return 0;
    return Number(numericValue.toFixed(2));
}

function formatTooltipValue(
    rawValue: number | string | ReadonlyArray<number | string> | undefined,
    metricName: number | string | undefined
): [string, string] {
    const candidateValue = Array.isArray(rawValue) ? rawValue[0] : rawValue;
    const parsedNumber = typeof candidateValue === 'number' ? candidateValue : Number(candidateValue ?? 0);
    const formatted = Number.isFinite(parsedNumber) ? String(roundTwo(parsedNumber)) : '0';
    return [formatted, String(metricName ?? '')];
}

export function computeEffectiveDomain(
    firstSeries?: number[],
    secondSeries?: number[],
    isPercentage?: boolean,
    explicitDomain?: [number, number]
): [number, number] {
    if (explicitDomain) return explicitDomain;
    if (isPercentage) return [0, 100];
    const firstValues = firstSeries && firstSeries.length > 0 ? firstSeries.filter(Number.isFinite) : [];
    const secondValues = secondSeries && secondSeries.length > 0 ? secondSeries.filter(Number.isFinite) : [];
    const maxFirst = firstValues.length > 0 ? Math.max(0, ...firstValues) : 0;
    const maxSecond = secondValues.length > 0 ? Math.max(0, ...secondValues) : 0;
    const combinedMax = Math.max(maxFirst, maxSecond);
    if (combinedMax <= 0) return [0, 10];
    const headroomCeiling = Math.ceil(combinedMax * 1.15);
    return [0, headroomCeiling];
}

function formatMagnitude(numericValue: number, unitLabel?: string): string {
    if (!Number.isFinite(numericValue)) return '0';
    if (unitLabel === 'B/s' || unitLabel === 'bytes') {
        if (numericValue >= 1073741824) return `${(numericValue / 1073741824).toFixed(1)} GB/s`;
        if (numericValue >= 1048576) return `${(numericValue / 1048576).toFixed(1)} MB/s`;
        if (numericValue >= 1024) return `${(numericValue / 1024).toFixed(1)} KB/s`;
        return `${numericValue.toFixed(0)} B/s`;
    }
    if (numericValue >= 1000000) return `${(numericValue / 1000000).toFixed(1)}M`;
    if (numericValue >= 1000) return `${(numericValue / 1000).toFixed(1)}k`;
    return `${numericValue.toFixed(numericValue % 1 === 0 ? 0 : 1)}${unitLabel ? ` ${unitLabel}` : ''}`;
}

export function buildChartData(
    data: number[] | undefined,
    data2?: number[],
    timestamps?: number[]
): ChartDataPoint[] {
    if (!data || data.length === 0) {
        return [];
    }
    const sampleCount = data.length;
    const alignment = validateTimestampsAlignment(sampleCount, timestamps);
    return data.map((numericValue, sampleIndex) => {
        const timestampMs = alignment.isValid && timestamps ? timestamps[sampleIndex] : undefined;
        const timeLabel = timestampMs ? formatTimeEndpoint(timestampMs) : undefined;
        return {
            name: timeLabel || `P${sampleIndex}`,
            index: sampleIndex,
            val1: roundTwo(numericValue),
            val2: data2 && data2[sampleIndex] !== undefined ? roundTwo(data2[sampleIndex]) : undefined,
            timestamp: timestampMs,
            timeLabel,
        };
    });
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
    effectiveDomain: [number, number];
    xAxisDomain: [number, number];
    isTimeScale: boolean;
    showDots: boolean;
    interpolation: 'linear' | 'monotone';
}

const MemoizedSparklineChart = React.memo(
    function MemoizedSparklineChart({
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
        effectiveDomain,
        xAxisDomain,
        isTimeScale,
        showDots,
        interpolation,
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

                    <XAxis
                        dataKey={isTimeScale ? 'timestamp' : 'index'}
                        type="number"
                        domain={xAxisDomain}
                        hide={true}
                    />

                    <YAxis domain={effectiveDomain} hide={true} />

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
                            type={interpolation}
                            dataKey="val2"
                            stroke={color2}
                            strokeWidth={strokeWidth}
                            fillOpacity={1}
                            fill={showArea ? `url(#${id}-g2)` : 'none'}
                            isAnimationActive={false}
                            name={label2 || 'Metric 2'}
                            dot={showDots ? { r: 3.5, fill: color2, stroke: '#0f172a', strokeWidth: 1.5 } : false}
                        />
                    )}
                    <Area
                        type={interpolation}
                        dataKey="val1"
                        stroke={color}
                        strokeWidth={strokeWidth}
                        fillOpacity={1}
                        fill={showArea ? `url(#${id}-g1)` : 'none'}
                        isAnimationActive={false}
                        name={label || 'Metric 1'}
                        dot={showDots ? { r: 3.5, fill: color, stroke: '#0f172a', strokeWidth: 1.5 } : false}
                    />
                </AreaChart>
            </ResponsiveContainer>
        );
    },
    (previousProps, nextProps) => {
        return (
            previousProps.chartData === nextProps.chartData &&
            previousProps.id === nextProps.id &&
            previousProps.color === nextProps.color &&
            previousProps.color2 === nextProps.color2 &&
            previousProps.gFrom === nextProps.gFrom &&
            previousProps.gTo === nextProps.gTo &&
            previousProps.gFrom2 === nextProps.gFrom2 &&
            previousProps.gTo2 === nextProps.gTo2 &&
            previousProps.strokeWidth === nextProps.strokeWidth &&
            previousProps.showArea === nextProps.showArea &&
            previousProps.hasData2 === nextProps.hasData2 &&
            previousProps.label === nextProps.label &&
            previousProps.label2 === nextProps.label2 &&
            previousProps.interpolation === nextProps.interpolation &&
            previousProps.isTimeScale === nextProps.isTimeScale &&
            previousProps.showDots === nextProps.showDots &&
            previousProps.effectiveDomain[0] === nextProps.effectiveDomain[0] &&
            previousProps.effectiveDomain[1] === nextProps.effectiveDomain[1] &&
            previousProps.xAxisDomain[0] === nextProps.xAxisDomain[0] &&
            previousProps.xAxisDomain[1] === nextProps.xAxisDomain[1]
        );
    }
);

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
    isPercentage = false,
    yDomain,
    showMagnitudeReferences = false,
    unit,
    timeContext,
    timestamps,
    selectedWindow,
    interpolation = 'linear',
    hasSharedSummary = false,
    variant = 'default',
}: SparklineProps) {
    const rawId = useId();
    const id = useMemo(() => rawId.replace(/:/g, ''), [rawId]);
    const [frozenChartData, setFrozenChartData] = useState<ChartDataPoint[] | null>(null);
    const [frozenDomain, setFrozenDomain] = useState<[number, number] | null>(null);
    const [frozenTimestamps, setFrozenTimestamps] = useState<number[] | null>(null);
    const [frozenXAxisDomain, setFrozenXAxisDomain] = useState<[number, number] | null>(null);

    const sampleCount = frozenChartData !== null ? frozenChartData.length : (data?.length || 0);
    const effectiveTimestamps = frozenTimestamps ?? timestamps;
    const alignment = validateTimestampsAlignment(sampleCount, effectiveTimestamps);
    const isTimeScale = alignment.isValid;
    const isDegenerateTimeSpan = Boolean(
        isTimeScale &&
        alignment.isValid &&
        alignment.startTimestamp !== undefined &&
        alignment.endTimestamp !== undefined &&
        alignment.startTimestamp === alignment.endTimestamp
    );
    const isSparseHistory = sampleCount < 2 || isDegenerateTimeSpan;
    const showDots = sampleCount === 1 || isDegenerateTimeSpan;

    const sparseStatusMessage = useMemo(() => {
        if (!isSparseHistory) {
            return null;
        }
        if (sampleCount === 0) {
            return 'Collecting · 0 samples';
        }
        if (sampleCount === 1) {
            return 'Collecting · 1 sample';
        }
        return `Collecting · ${sampleCount} samples · 0s span`;
    }, [isSparseHistory, sampleCount]);

    const sparseMetadataMessage = useMemo(() => {
        if (!isSparseHistory) {
            return null;
        }
        const hasObservedTime = Boolean(
            alignment.isValid &&
            effectiveTimestamps &&
            effectiveTimestamps.length > 0
        );
        const observedTimeText = hasObservedTime
            ? `Observed ${formatTimeEndpoint(alignment.startTimestamp ?? effectiveTimestamps![0])}`
            : null;

        if (observedTimeText && selectedWindow) {
            return `${observedTimeText} · ${selectedWindow} max`;
        }
        if (observedTimeText) {
            return observedTimeText;
        }
        if (selectedWindow) {
            return `${selectedWindow} max`;
        }
        return null;
    }, [isSparseHistory, alignment, effectiveTimestamps, selectedWindow]);

    const calculatedXAxisDomain = useMemo<[number, number]>(() => {
        return computeEffectiveXDomain(sampleCount, alignment);
    }, [sampleCount, alignment]);
    const effectiveXAxisDomain = frozenXAxisDomain ?? calculatedXAxisDomain;

    const activeChartData = useMemo<ChartDataPoint[]>(() => {
        if (frozenChartData !== null) {
            return frozenChartData;
        }
        return buildChartData(data, data2, effectiveTimestamps);
    }, [frozenChartData, data, data2, effectiveTimestamps]);

    const calculatedDomain = useMemo<[number, number]>(() => {
        return computeEffectiveDomain(data, data2, isPercentage, yDomain);
    }, [data, data2, isPercentage, yDomain]);

    const effectiveDomain = useMemo<[number, number]>(() => {
        if (frozenDomain !== null) {
            return frozenDomain;
        }
        return calculatedDomain;
    }, [frozenDomain, calculatedDomain]);

    const handleMouseEnter = useCallback(() => {
        setFrozenChartData((previous) => previous ?? activeChartData);
        setFrozenDomain((previous) => previous ?? calculatedDomain);
        setFrozenTimestamps((previous) => previous ?? (timestamps ? [...timestamps] : null));
        setFrozenXAxisDomain((previous) => previous ?? calculatedXAxisDomain);
    }, [activeChartData, calculatedDomain, timestamps, calculatedXAxisDomain]);

    const handleMouseLeave = useCallback(() => {
        setFrozenChartData(null);
        setFrozenDomain(null);
        setFrozenTimestamps(null);
        setFrozenXAxisDomain(null);
    }, []);

    const resolvedTimeContext = computeTimeContext({
        sampleCount,
        timestamps: effectiveTimestamps,
        selectedWindow,
        explicitTimeContext: timeContext,
    });

    const gFrom = gradientFrom || color;
    const gTo = gradientTo || 'transparent';
    const gFrom2 = gradientFrom2 || color2;
    const gTo2 = gradientTo2 || 'transparent';

    if (isSparseHistory) {
        if (variant === 'mini') {
            return (
                <div className={`relative w-full min-w-0 max-w-full ${className}`} style={{ height }}>
                    <span className="sr-only">{sparseStatusMessage}</span>
                </div>
            );
        }
        return (
            <div
                className={`relative select-none flex flex-col w-full min-w-0 max-w-full py-1 ${className}`}
                style={{ touchAction: 'pan-y' }}
                onMouseEnter={handleMouseEnter}
                onMouseLeave={handleMouseLeave}
                onTouchStart={handleMouseEnter}
                onTouchEnd={handleMouseLeave}
                onTouchCancel={handleMouseLeave}
            >
                {(label || label2) ? (
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 min-w-0 max-w-full">
                        {label && (
                            <div className="flex items-center gap-1.5">
                                <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
                                <span className="text-xs font-medium text-slate-400">{label}</span>
                                {currentValue && <span className="sr-only">{currentValue}</span>}
                            </div>
                        )}
                        {label2 && (
                            <div className="flex items-center gap-1.5">
                                <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color2 }} />
                                <span className="text-xs font-medium text-slate-400">{label2}</span>
                                {currentValue2 && <span className="sr-only">{currentValue2}</span>}
                            </div>
                        )}
                    </div>
                ) : hasSharedSummary ? (
                    <div className="flex items-center gap-2 text-xs font-mono text-slate-400 min-w-0 max-w-full">
                        <span className="w-1.5 h-1.5 rounded-full bg-indigo-400/80 shrink-0" />
                        <span
                            data-testid="sparse-history-qualifier"
                            className="tabular-nums whitespace-normal break-words leading-tight min-w-0 max-w-full truncate text-slate-300"
                        >
                            History collecting
                        </span>
                    </div>
                ) : null}
                {hasSharedSummary ? null : (
                    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs font-mono text-slate-400 min-w-0 max-w-full">
                        {sparseStatusMessage && (
                            <span
                                data-testid="sparse-history-status"
                                className="tabular-nums whitespace-normal break-words leading-normal min-w-0 max-w-full shrink"
                            >
                                {sparseStatusMessage}
                            </span>
                        )}
                        {sparseMetadataMessage && (
                            <span
                                data-testid="sparse-history-metadata"
                                className="tabular-nums whitespace-normal break-words leading-normal min-w-0 max-w-full shrink text-slate-400"
                            >
                                {sparseMetadataMessage}
                            </span>
                        )}
                    </div>
                )}
            </div>
        );
    }

    return (
        <div
            className={`relative select-none flex flex-col w-full min-w-0 max-w-full ${className}`}
            style={{ touchAction: 'pan-y' }}
            onMouseEnter={handleMouseEnter}
            onMouseLeave={handleMouseLeave}
            onTouchStart={handleMouseEnter}
            onTouchEnd={handleMouseLeave}
            onTouchCancel={handleMouseLeave}
        >
            {variant !== 'mini' && (label || label2 || resolvedTimeContext) && (
                <div className={`${hasSharedSummary && !label && !label2 ? 'sr-only' : 'flex flex-wrap items-center justify-between gap-x-3 gap-y-1 mb-2 z-10 relative pointer-events-none w-full min-w-0 max-w-full'}`}>
                    {(label || label2) && (
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 min-w-0 max-w-full">
                            {label && (
                                <div className="flex items-center gap-1.5">
                                    <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
                                    <span className="text-xs font-medium text-slate-400">{label}</span>
                                    {currentValue && <span className="sr-only">{currentValue}</span>}
                                </div>
                            )}
                            {label2 && (
                                <div className="flex items-center gap-1.5">
                                    <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color2 }} />
                                    <span className="text-xs font-medium text-slate-400">{label2}</span>
                                    {currentValue2 && <span className="sr-only">{currentValue2}</span>}
                                </div>
                            )}
                        </div>
                    )}
                    {resolvedTimeContext ? (
                        <span className={hasSharedSummary ? 'sr-only' : 'text-xs font-mono text-slate-400 tabular-nums min-w-0'}>
                            {resolvedTimeContext}
                        </span>
                    ) : null}
                </div>
            )}
            <div style={{ height: height, touchAction: 'pan-y' }} className="w-full relative flex gap-2">
                <div className="flex-1 min-w-0 h-full relative">
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
                        effectiveDomain={effectiveDomain}
                        xAxisDomain={effectiveXAxisDomain}
                        isTimeScale={isTimeScale}
                        showDots={showDots}
                        interpolation={interpolation}
                    />
                </div>
                {showMagnitudeReferences && variant !== 'mini' && (
                    <div className="shrink-0 flex flex-col justify-between items-end py-0.5 pointer-events-none text-xs font-mono text-slate-300 select-none">
                        <span className="tabular-nums leading-none">
                            {isPercentage ? '100%' : formatMagnitude(effectiveDomain[1], unit)}
                        </span>
                        <span className="tabular-nums leading-none">
                            {isPercentage ? '50%' : formatMagnitude(effectiveDomain[1] / 2, unit)}
                        </span>
                        <span className="tabular-nums leading-none">
                            {isPercentage ? '0%' : (unit ? `0 ${unit}` : '0')}
                        </span>
                    </div>
                )}
            </div>
            {sampleCount > 0 && variant !== 'mini' && (
                <div className="flex flex-wrap items-center justify-between gap-x-2 text-xs font-mono text-slate-400 pt-1.5 select-none">
                    <span>
                        {alignment.isValid && effectiveTimestamps
                            ? formatTimeEndpoint(alignment.startTimestamp ?? effectiveTimestamps[0])
                            : 'Sample 1'}
                    </span>
                    <span className="sr-only">
                        {sampleCount === 1
                            ? 'single sample'
                            : alignment.isValid && alignment.spanSeconds !== undefined
                                ? `${formatDurationSpan(alignment.spanSeconds)} span`
                                : `${sampleCount} samples (sequence)`}
                    </span>
                    <span>
                        {alignment.isValid && effectiveTimestamps
                            ? formatTimeEndpoint(alignment.endTimestamp ?? effectiveTimestamps[effectiveTimestamps.length - 1])
                            : (sampleCount === 1 ? 'Sample 1' : `Sample ${sampleCount}`)}
                    </span>
                </div>
            )}
        </div>
    );
}
