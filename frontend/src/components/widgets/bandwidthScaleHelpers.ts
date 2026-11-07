export interface LinearByteScale {
    domain: [number, number];
    ticks: number[];
    unit: string;
    formatTick: (bytesCount: number) => string;
}

interface ByteUnitTier {
    unit: string;
    bytes: number;
}

const BYTE_UNIT_TIERS: ByteUnitTier[] = [
    { unit: 'PB', bytes: 1024 ** 5 },
    { unit: 'TB', bytes: 1024 ** 4 },
    { unit: 'GB', bytes: 1024 ** 3 },
    { unit: 'MB', bytes: 1024 ** 2 },
    { unit: 'KB', bytes: 1024 },
    { unit: 'B', bytes: 1 },
];

const NICE_MULTIPLIERS: number[] = [1, 2, 2.5, 4, 5, 10];

export function computeNiceByteScale(maxDataBytes: number): LinearByteScale {
    if (!Number.isFinite(maxDataBytes) || maxDataBytes <= 0) {
        return {
            domain: [0, 4],
            ticks: [0, 1, 2, 3, 4],
            unit: 'B',
            formatTick: (bytesCount: number): string => `${Math.round(bytesCount)} B`,
        };
    }

    const selectedTier = BYTE_UNIT_TIERS.find((tierItem) => maxDataBytes >= tierItem.bytes) || {
        unit: 'B',
        bytes: 1,
    };

    const maxInUnit = maxDataBytes / selectedTier.bytes;
    const rawStepInUnit = maxInUnit / 4;

    const stepExponent = Math.floor(Math.log10(rawStepInUnit));
    const stepMagnitude = Math.pow(10, stepExponent);
    const normalizedStep = rawStepInUnit / stepMagnitude;

    let chosenMultiplier = 10;
    for (const multiplierCandidate of NICE_MULTIPLIERS) {
        if (multiplierCandidate >= normalizedStep - 1e-9) {
            chosenMultiplier = multiplierCandidate;
            break;
        }
    }

    const niceStepInUnit = chosenMultiplier * stepMagnitude;
    const stepInBytes = niceStepInUnit * selectedTier.bytes;

    const generatedTicks = [
        0,
        stepInBytes,
        2 * stepInBytes,
        3 * stepInBytes,
        4 * stepInBytes,
    ];

    const formatTick = (bytesCount: number): string => {
        const valueInUnit = bytesCount / selectedTier.bytes;
        if (Math.abs(valueInUnit - Math.round(valueInUnit)) < 1e-5) {
            return `${Math.round(valueInUnit)} ${selectedTier.unit}`;
        }
        const formattedDecimal = parseFloat(valueInUnit.toFixed(2));
        return `${formattedDecimal} ${selectedTier.unit}`;
    };

    return {
        domain: [0, generatedTicks[4]],
        ticks: generatedTicks,
        unit: selectedTier.unit,
        formatTick,
    };
}
