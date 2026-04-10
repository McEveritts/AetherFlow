'use client';

import { useState, useEffect } from 'react';

export interface ProgressRingProps {
    progress: number;      // 0-100
    status: string;        // "installing" | "uninstalling"
    logLine?: string;
    startedAt?: string;
    size?: number;
    stroke?: number;
}

export function ProgressRing({ progress, status, logLine, startedAt, size = 72, stroke = 4 }: ProgressRingProps) {
    const [elapsed, setElapsed] = useState('0s');

    useEffect(() => {
        if (!startedAt) return;
        const start = new Date(startedAt).getTime();
        const update = () => {
            const diff = Math.floor((Date.now() - start) / 1000);
            if (diff < 60) setElapsed(`${diff}s`);
            else setElapsed(`${Math.floor(diff / 60)}m ${diff % 60}s`);
        };
        update();
        const interval = setInterval(update, 1000);
        return () => clearInterval(interval);
    }, [startedAt]);

    const radius = (size - stroke) / 2;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (progress / 100) * circumference;
    const isUninstalling = status === 'uninstalling';
    const color = isUninstalling ? '#ef4444' : '#818cf8'; // red for uninstall, indigo for install
    const glowColor = isUninstalling ? 'rgba(239,68,68,0.5)' : 'rgba(99,102,241,0.5)';
    const label = isUninstalling ? 'Removing' : 'Installing';

    // Truncate log line for display
    const displayLine = logLine && logLine.length > 40 ? logLine.slice(0, 37) + '...' : logLine;

    return (
        <div className="flex flex-col items-center gap-2 animate-fade-in">
            <div className="relative" style={{ width: size, height: size }}>
                {/* Glow effect */}
                <div
                    className="absolute inset-0 rounded-full animate-pulse"
                    style={{
                        boxShadow: `0 0 20px ${glowColor}, 0 0 40px ${glowColor}`,
                        opacity: 0.4,
                    }}
                />
                <svg width={size} height={size} className="transform -rotate-90">
                    {/* Background track */}
                    <circle
                        cx={size / 2}
                        cy={size / 2}
                        r={radius}
                        fill="none"
                        stroke="rgba(255,255,255,0.06)"
                        strokeWidth={stroke}
                    />
                    {/* Progress arc */}
                    <circle
                        cx={size / 2}
                        cy={size / 2}
                        r={radius}
                        fill="none"
                        stroke={color}
                        strokeWidth={stroke}
                        strokeLinecap="round"
                        strokeDasharray={circumference}
                        strokeDashoffset={offset}
                        style={{
                            transition: 'stroke-dashoffset 0.6s ease-out',
                            filter: `drop-shadow(0 0 6px ${glowColor})`,
                        }}
                    />
                </svg>
                {/* Percentage text */}
                <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-base font-bold text-white tabular-nums">
                        {progress}%
                    </span>
                </div>
            </div>
            <div className="text-center space-y-0.5">
                <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                    {label} · {elapsed}
                </div>
                {displayLine && (
                    <div className="text-[9px] text-slate-500 max-w-[180px] truncate">
                        {displayLine}
                    </div>
                )}
            </div>
        </div>
    );
}
