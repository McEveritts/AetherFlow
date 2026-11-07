export interface LinearScaleConfig {
    domain: [number, number];
    ticks: number[];
}

export interface NiceScaleOptions {
    integerOnly?: boolean;
    minCeiling?: number;
    intervalCount?: number;
}

export interface DualAxisScales {
    leftAxis: LinearScaleConfig;
    rightAxis: LinearScaleConfig;
}

export function computeNiceLinearScale(
    dataMaxInput: number,
    options?: NiceScaleOptions
): LinearScaleConfig {
    const intervalCount = options?.intervalCount && options.intervalCount > 0 ? options.intervalCount : 4;
    const integerOnly = Boolean(options?.integerOnly);
    const minCeiling = options?.minCeiling !== undefined && Number.isFinite(options.minCeiling)
        ? Math.max(0, options.minCeiling)
        : (integerOnly ? 4 : 1);

    const safeDataMax = Number.isFinite(dataMaxInput) ? Math.max(0, dataMaxInput) : 0;
    const rawCeiling = Math.max(safeDataMax, minCeiling);

    if (rawCeiling === 0) {
        const fallbackTicks: number[] = [];
        for (let stepIndex = 0; stepIndex <= intervalCount; stepIndex += 1) {
            fallbackTicks.push(stepIndex);
        }
        return {
            domain: [0, intervalCount],
            ticks: fallbackTicks,
        };
    }

    const rawStep = rawCeiling / intervalCount;
    const powerOfTen = Math.pow(10, Math.floor(Math.log10(rawStep)));
    const normalizedFraction = rawStep / powerOfTen;

    let niceStepFraction: number;
    if (integerOnly) {
        if (powerOfTen < 1) {
            niceStepFraction = 1 / powerOfTen;
        } else if (normalizedFraction <= 1) {
            niceStepFraction = 1;
        } else if (normalizedFraction <= 2) {
            niceStepFraction = 2;
        } else if (normalizedFraction <= 5) {
            niceStepFraction = 5;
        } else {
            niceStepFraction = 10;
        }
    } else {
        if (normalizedFraction <= 1) {
            niceStepFraction = 1;
        } else if (normalizedFraction <= 2) {
            niceStepFraction = 2;
        } else if (normalizedFraction <= 2.5) {
            niceStepFraction = 2.5;
        } else if (normalizedFraction <= 5) {
            niceStepFraction = 5;
        } else {
            niceStepFraction = 10;
        }
    }

    const finalStep = Math.max(integerOnly ? 1 : 0.0001, niceStepFraction * powerOfTen);

    const stepString = finalStep.toString();
    const decimalPlaces = stepString.includes('.') ? stepString.split('.')[1].length : 0;
    const precisionDecimals = Math.min(6, decimalPlaces);

    const ticks: number[] = [];
    for (let stepIndex = 0; stepIndex <= intervalCount; stepIndex += 1) {
        const rawTick = stepIndex * finalStep;
        const formattedTick = precisionDecimals > 0 ? Number(rawTick.toFixed(precisionDecimals)) : Math.round(rawTick);
        ticks.push(formattedTick);
    }

    return {
        domain: [0, ticks[ticks.length - 1]],
        ticks,
    };
}

export function computeDualLinearScales(
    leftMaxInput: number,
    rightMaxInput: number,
    options?: {
        leftIntegerOnly?: boolean;
        rightIntegerOnly?: boolean;
        leftMinCeiling?: number;
        rightMinCeiling?: number;
        intervalCount?: number;
    }
): DualAxisScales {
    const intervalCount = options?.intervalCount && options.intervalCount > 0 ? options.intervalCount : 4;
    const leftScale = computeNiceLinearScale(leftMaxInput, {
        integerOnly: options?.leftIntegerOnly,
        minCeiling: options?.leftMinCeiling,
        intervalCount,
    });
    const rightScale = computeNiceLinearScale(rightMaxInput, {
        integerOnly: options?.rightIntegerOnly,
        minCeiling: options?.rightMinCeiling,
        intervalCount,
    });
    return {
        leftAxis: leftScale,
        rightAxis: rightScale,
    };
}

export function formatStreamingAxisDateTick(
    value: unknown,
    granularity: 'day' | 'month' | 'year' = 'day'
): string {
    const rawValue = String(value ?? '').trim();
    if (!rawValue) return '';
    if (granularity === 'year') {
        const yearComponents = rawValue.split('-');
        return yearComponents[0] || rawValue;
    }
    if (granularity === 'month') {
        const monthComponents = rawValue.split('-');
        if (monthComponents.length >= 2) {
            const shortYear = monthComponents[0].slice(-2);
            const monthNumber = monthComponents[1];
            return `${monthNumber}/${shortYear}`;
        }
        return rawValue.slice(0, 7);
    }
    const dayComponents = rawValue.split('-');
    if (dayComponents.length >= 3) {
        const monthNumber = dayComponents[1];
        const dayNumber = dayComponents[2].slice(0, 2);
        return `${monthNumber}/${dayNumber}`;
    }
    return rawValue;
}
