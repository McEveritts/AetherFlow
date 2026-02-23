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
        <div className="space-y-6 animate-fade-in w-full">
            <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3 mb-8">
                <SkeletonBox className="h-6 w-6 rounded-md bg-white/10" animated={false} />
                <SkeletonBox className="h-8 w-48 rounded-md bg-white/10" animated={false} />
            </h2>

            {/* Metric Cards Skeleton Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
                {[...Array(4)].map((_, i) => (
                    <SkeletonBox key={i} className="h-40 w-full" />
                ))}
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                {/* Large Chart Skeleton */}
                <SkeletonBox className="col-span-1 xl:col-span-2 h-[400px]" />

                {/* Sidebar Cards Skeleton */}
                <div className="space-y-6">
                    <SkeletonBox className="h-[250px] w-full" />
                    <SkeletonBox className="h-[250px] w-full" />
                </div>
            </div>
        </div>
    );
}
