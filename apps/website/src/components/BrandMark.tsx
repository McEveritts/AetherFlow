import { useId } from 'react';

interface BrandMarkProps {
  className?: string;
  decorative?: boolean;
}

export function BrandMark({
  className = 'h-8 w-8',
  decorative = true,
}: BrandMarkProps) {
  const uid = useId().replace(/:/g, '');
  const peakId = `afm-peak-${uid}`;
  const flowId = `afm-flow-${uid}`;
  const clipId = `afm-clip-${uid}`;
  const cutPeakId = `afm-cut-peak-${uid}`;
  const cutFlowId = `afm-cut-flow-${uid}`;

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 128 128"
      className={className}
      aria-hidden={decorative ? 'true' : undefined}
      role={decorative ? undefined : 'img'}
      aria-label={decorative ? undefined : 'AetherFlow'}
    >
      <defs>
        <linearGradient
          id={peakId}
          x1="24"
          y1="104"
          x2="104"
          y2="24"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0" stopColor="#38bdf8" />
          <stop offset="0.5" stopColor="#6366f1" />
          <stop offset="1" stopColor="#a855f7" />
        </linearGradient>
        <linearGradient
          id={flowId}
          x1="10"
          y1="0"
          x2="118"
          y2="0"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0" stopColor="#22d3ee" stopOpacity="0" />
          <stop offset="0.3" stopColor="#22d3ee" />
          <stop offset="1" stopColor="#c084fc" />
        </linearGradient>
        <clipPath id={clipId}>
          <rect x="0" y="0" width="64" height="128" />
        </clipPath>
        <mask
          id={cutPeakId}
          maskUnits="userSpaceOnUse"
          x="0"
          y="0"
          width="128"
          height="128"
        >
          <rect width="128" height="128" fill="#fff" />
          <path
            d="M12 82 C28 82 32 66 48 66 S72 82 88 78 S108 60 116 58"
            fill="none"
            stroke="#000"
            strokeWidth="22"
            strokeLinecap="round"
            clipPath={`url(#${clipId})`}
          />
        </mask>
        <mask
          id={cutFlowId}
          maskUnits="userSpaceOnUse"
          x="0"
          y="0"
          width="128"
          height="128"
        >
          <rect width="128" height="128" fill="#fff" />
          <path d="M64 26 L98 100" fill="none" stroke="#000" strokeWidth="23" />
        </mask>
      </defs>

      <path
        d="M30 100 L64 26 L98 100"
        fill="none"
        stroke={`url(#${peakId})`}
        strokeWidth="13"
        strokeLinecap="round"
        strokeLinejoin="round"
        mask={`url(#${cutPeakId})`}
      />
      <path
        d="M12 82 C28 82 32 66 48 66 S72 82 88 78 S108 60 116 58"
        fill="none"
        stroke={`url(#${flowId})`}
        strokeWidth="10"
        strokeLinecap="round"
        mask={`url(#${cutFlowId})`}
      />
      <circle cx="116" cy="58" r="11" fill="#c084fc" fillOpacity="0.2" />
      <circle cx="116" cy="58" r="6.5" fill="#c084fc" />
    </svg>
  );
}
