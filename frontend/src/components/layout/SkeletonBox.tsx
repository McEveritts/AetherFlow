export default function SkeletonBox({ className = "", animated = true }: { className?: string; animated?: boolean }) {
    return (
        <div
            className={`
                bg-white/[0.03] backdrop-blur-xl border border-white/[0.05] rounded-2xl
                ${animated ? 'animate-pulse' : ''} 
                ${className}
            `}
        />
    );
}

export function OverviewSkeleton() {
    return (
        <div className="space-y-5 animate-fade-in w-full">
            {/* Top Command Header Skeleton */}
            <div className="flex items-center justify-between pb-4 border-b border-white/[0.06]">
                <div className="flex items-center gap-3.5">
                    <SkeletonBox className="h-11 w-11 rounded-2xl bg-indigo-500/20" animated={false} />
                    <div className="space-y-2">
                        <SkeletonBox className="h-6 w-48 rounded-md bg-white/10" animated={false} />
                        <SkeletonBox className="h-3.5 w-72 rounded-md bg-white/5" animated={false} />
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <SkeletonBox className="h-9 w-36 rounded-xl bg-white/5" animated={false} />
                    <SkeletonBox className="h-9 w-24 rounded-xl bg-white/5" animated={false} />
                </div>
            </div>

            {/* 6-Cell Telemetry Ribbon Skeleton */}
            <SkeletonBox className="h-20 w-full rounded-2xl" />

            {/* Band 1: 4-Column Real-Time Vitals */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                {[...Array(4)].map((_, i) => (
                    <SkeletonBox key={i} className="h-60 w-full rounded-2xl" />
                ))}
            </div>

            {/* Band 2: Topology & Bandwidth History */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
                <SkeletonBox className="xl:col-span-6 h-[380px] rounded-2xl" />
                <SkeletonBox className="xl:col-span-6 h-[380px] rounded-2xl" />
            </div>

            {/* Band 3: Storage, Accelerators & Processes */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
                <SkeletonBox className="xl:col-span-4 h-[320px] rounded-2xl" />
                <SkeletonBox className="xl:col-span-4 h-[320px] rounded-2xl" />
                <SkeletonBox className="xl:col-span-4 h-[320px] rounded-2xl" />
            </div>
        </div>
    );
}

export function ServicesSkeleton() {
    return (
        <div className="space-y-8 animate-fade-in w-full">
            <div className="flex justify-between items-end">
                <div className="space-y-2">
                    <SkeletonBox className="h-8 w-48 rounded-md bg-white/10" animated={false} />
                    <SkeletonBox className="h-4 w-64 rounded-md bg-white/5" animated={false} />
                </div>
                <SkeletonBox className="h-10 w-28 rounded-xl bg-white/5" animated={false} />
            </div>

            <div className="space-y-4">
                <SkeletonBox className="h-5 w-32 rounded-md bg-white/5" animated={false} />
                <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
                    {[...Array(6)].map((_, i) => (
                        <SkeletonBox key={i} className="h-[238px] w-full rounded-2xl" />
                    ))}
                </div>
            </div>
        </div>
    );
}

export function UsersSkeleton() {
    return (
        <div className="space-y-6 animate-fade-in max-w-5xl w-full">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <SkeletonBox className="h-12 w-12 rounded-xl bg-indigo-500/20" animated={false} />
                    <div className="space-y-2">
                        <SkeletonBox className="h-8 w-48 rounded-md bg-white/10" animated={false} />
                        <SkeletonBox className="h-4 w-64 rounded-md bg-white/5" animated={false} />
                    </div>
                </div>
                <SkeletonBox className="h-10 w-32 rounded-xl bg-white/5" animated={false} />
            </div>

            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl overflow-hidden p-6 space-y-4">
                <SkeletonBox className="h-12 w-full rounded-xl bg-white/5" animated={false} />
                {[...Array(5)].map((_, i) => (
                    <SkeletonBox key={i} className="h-16 w-full rounded-xl" />
                ))}
            </div>
        </div>
    );
}

export function SettingsSkeleton() {
    return (
        <div className="space-y-8 animate-fade-in relative pb-12 w-full">
            <div className="space-y-2">
                <SkeletonBox className="h-8 w-64 rounded-md bg-white/10" animated={false} />
                <SkeletonBox className="h-4 w-96 rounded-md bg-white/5" animated={false} />
            </div>

            <div className="flex flex-wrap gap-2 pb-4 border-b border-white/[0.06]">
                {[...Array(9)].map((_, i) => (
                    <SkeletonBox key={i} className="h-9 w-28 rounded-xl bg-white/5" animated={false} />
                ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 w-full">
                <div className="glass-panel border border-white/[0.06] rounded-2xl p-6 space-y-5">
                    <SkeletonBox className="h-6 w-48 rounded-md bg-white/5" animated={false} />
                    <SkeletonBox className="h-24 w-full rounded-xl" />
                    <SkeletonBox className="h-24 w-full rounded-xl" />
                    <SkeletonBox className="h-24 w-full rounded-xl" />
                </div>

                <div className="glass-panel border border-white/[0.06] rounded-2xl p-6 space-y-5">
                    <SkeletonBox className="h-6 w-48 rounded-md bg-white/5" animated={false} />
                    <SkeletonBox className="h-24 w-full rounded-xl" />
                    <SkeletonBox className="h-24 w-full rounded-xl" />
                    <SkeletonBox className="h-24 w-full rounded-xl" />
                </div>
            </div>

            <SkeletonBox className="h-16 w-full rounded-2xl bg-white/[0.02]" animated={false} />
        </div>
    );
}
