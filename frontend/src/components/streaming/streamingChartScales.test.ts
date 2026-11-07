import { computeNiceLinearScale, computeDualLinearScales, formatStreamingAxisDateTick } from './streamingChartScales';

describe('streamingChartScales', () => {
    it('generates equal-count linear ticks and nice ceilings for standard positive values', () => {
        const bandwidthScale = computeNiceLinearScale(59.2, { minCeiling: 10, intervalCount: 4 });
        expect(bandwidthScale.ticks).toEqual([0, 20, 40, 60, 80]);
        expect(bandwidthScale.domain).toEqual([0, 80]);

        const hoursScale = computeNiceLinearScale(13.6, { minCeiling: 1, intervalCount: 4 });
        expect(hoursScale.ticks).toEqual([0, 5, 10, 15, 20]);
        expect(hoursScale.domain).toEqual([0, 20]);
    });

    it('enforces integer-only ticks for play counts and session metrics', () => {
        const playCountsScale = computeNiceLinearScale(7, { integerOnly: true, minCeiling: 4, intervalCount: 4 });
        expect(playCountsScale.ticks).toEqual([0, 2, 4, 6, 8]);
        expect(playCountsScale.ticks.every((tickValue) => Number.isInteger(tickValue))).toBe(true);

        const largePlayScale = computeNiceLinearScale(15, { integerOnly: true, minCeiling: 4, intervalCount: 4 });
        expect(largePlayScale.ticks).toEqual([0, 5, 10, 15, 20]);
        expect(largePlayScale.ticks.every((tickValue) => Number.isInteger(tickValue))).toBe(true);
    });

    it('handles zero, negative, and nonfinite values gracefully using minCeiling', () => {
        const zeroScale = computeNiceLinearScale(0, { minCeiling: 10, intervalCount: 4 });
        expect(zeroScale.ticks).toEqual([0, 2.5, 5, 7.5, 10]);
        expect(zeroScale.domain).toEqual([0, 10]);

        const nanScale = computeNiceLinearScale(Number.NaN, { minCeiling: 4, integerOnly: true, intervalCount: 4 });
        expect(nanScale.ticks).toEqual([0, 1, 2, 3, 4]);

        const negativeScale = computeNiceLinearScale(-25, { minCeiling: 4, integerOnly: true, intervalCount: 4 });
        expect(negativeScale.ticks).toEqual([0, 1, 2, 3, 4]);
    });

    it('synchronizes tick counts across dual axes in a chart', () => {
        const dualScales = computeDualLinearScales(22.4, 59.2, {
            leftMinCeiling: 4,
            rightMinCeiling: 10,
            intervalCount: 4,
        });

        expect(dualScales.leftAxis.ticks).toHaveLength(5);
        expect(dualScales.rightAxis.ticks).toHaveLength(5);
        expect(dualScales.leftAxis.ticks.length).toBe(dualScales.rightAxis.ticks.length);
        expect(dualScales.leftAxis.ticks[0]).toBe(0);
        expect(dualScales.rightAxis.ticks[0]).toBe(0);
    });

    it('scales dynamically to very large numbers without hardcoded limits', () => {
        const largeScale = computeNiceLinearScale(1850000, { intervalCount: 4 });
        expect(largeScale.ticks).toEqual([0, 500000, 1000000, 1500000, 2000000]);
        expect(largeScale.domain).toEqual([0, 2000000]);
    });

    it('shortens axis date ticks for day, month, and year granularity while handling edge cases', () => {
        expect(formatStreamingAxisDateTick('2026-11-05', 'day')).toBe('11/05');
        expect(formatStreamingAxisDateTick('2024-05-31', 'day')).toBe('05/31');
        expect(formatStreamingAxisDateTick('2026-11-05', 'month')).toBe('11/26');
        expect(formatStreamingAxisDateTick('2024-05', 'month')).toBe('05/24');
        expect(formatStreamingAxisDateTick('2026-01-01', 'year')).toBe('2026');
        expect(formatStreamingAxisDateTick('2024', 'year')).toBe('2024');
        expect(formatStreamingAxisDateTick('', 'day')).toBe('');
        expect(formatStreamingAxisDateTick(null, 'day')).toBe('');
        expect(formatStreamingAxisDateTick(undefined, 'month')).toBe('');
    });
});
