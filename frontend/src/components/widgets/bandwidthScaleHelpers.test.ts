import { computeNiceByteScale } from '@/components/widgets/bandwidthScaleHelpers';

describe('computeNiceByteScale linear axis scales and tick formatting', () => {
    it('returns truthful integer byte ticks for zero and negative boundary conditions', () => {
        const zeroScale = computeNiceByteScale(0);
        expect(zeroScale.domain).toEqual([0, 4]);
        expect(zeroScale.ticks).toEqual([0, 1, 2, 3, 4]);
        expect(zeroScale.unit).toBe('B');
        expect(zeroScale.ticks.map(zeroScale.formatTick)).toEqual([
            '0 B',
            '1 B',
            '2 B',
            '3 B',
            '4 B',
        ]);

        const negativeScale = computeNiceByteScale(-1024);
        expect(negativeScale.domain).toEqual([0, 4]);
        expect(negativeScale.ticks).toEqual([0, 1, 2, 3, 4]);
    });

    it('creates uniform linear ticks for small byte payloads without uneven intervals', () => {
        const smallScale = computeNiceByteScale(500);
        expect(smallScale.domain).toEqual([0, 800]);
        expect(smallScale.ticks).toEqual([0, 200, 400, 600, 800]);
        expect(smallScale.unit).toBe('B');
        expect(smallScale.ticks.map(smallScale.formatTick)).toEqual([
            '0 B',
            '200 B',
            '400 B',
            '600 B',
            '800 B',
        ]);

        const firstInterval = smallScale.ticks[1] - smallScale.ticks[0];
        const secondInterval = smallScale.ticks[2] - smallScale.ticks[1];
        const thirdInterval = smallScale.ticks[3] - smallScale.ticks[2];
        const fourthInterval = smallScale.ticks[4] - smallScale.ticks[3];

        expect(firstInterval).toBe(200);
        expect(secondInterval).toBe(200);
        expect(thirdInterval).toBe(200);
        expect(fourthInterval).toBe(200);
    });

    it('solves the 15GB scale by generating exact 4GB linear steps and uniform GB labels', () => {
        const gigabyteBytes = 1024 * 1024 * 1024;
        const fifteenGigabytes = 15 * gigabyteBytes;
        const scaleResult = computeNiceByteScale(fifteenGigabytes);

        expect(scaleResult.unit).toBe('GB');
        expect(scaleResult.domain).toEqual([0, 16 * gigabyteBytes]);
        expect(scaleResult.ticks).toEqual([
            0,
            4 * gigabyteBytes,
            8 * gigabyteBytes,
            12 * gigabyteBytes,
            16 * gigabyteBytes,
        ]);
        expect(scaleResult.ticks.map(scaleResult.formatTick)).toEqual([
            '0 GB',
            '4 GB',
            '8 GB',
            '12 GB',
            '16 GB',
        ]);

        const stepDifferences = [
            scaleResult.ticks[1] - scaleResult.ticks[0],
            scaleResult.ticks[2] - scaleResult.ticks[1],
            scaleResult.ticks[3] - scaleResult.ticks[2],
            scaleResult.ticks[4] - scaleResult.ticks[3],
        ];
        expect(stepDifferences).toEqual([
            4 * gigabyteBytes,
            4 * gigabyteBytes,
            4 * gigabyteBytes,
            4 * gigabyteBytes,
        ]);
    });

    it('handles decimal step ticks accurately for 10GB input payload', () => {
        const gigabyteBytes = 1024 * 1024 * 1024;
        const tenGigabytes = 10 * gigabyteBytes;
        const scaleResult = computeNiceByteScale(tenGigabytes);

        expect(scaleResult.unit).toBe('GB');
        expect(scaleResult.domain).toEqual([0, 10 * gigabyteBytes]);
        expect(scaleResult.ticks.map(scaleResult.formatTick)).toEqual([
            '0 GB',
            '2.5 GB',
            '5 GB',
            '7.5 GB',
            '10 GB',
        ]);
    });

    it('handles large volume scales like 100GB with uniform steps and matching unit framing', () => {
        const gigabyteBytes = 1024 * 1024 * 1024;
        const hundredGigabytes = 100 * gigabyteBytes;
        const scaleResult = computeNiceByteScale(hundredGigabytes);

        expect(scaleResult.unit).toBe('GB');
        expect(scaleResult.domain).toEqual([0, 100 * gigabyteBytes]);
        expect(scaleResult.ticks).toEqual([
            0,
            25 * gigabyteBytes,
            50 * gigabyteBytes,
            75 * gigabyteBytes,
            100 * gigabyteBytes,
        ]);
        expect(scaleResult.ticks.map(scaleResult.formatTick)).toEqual([
            '0 GB',
            '25 GB',
            '50 GB',
            '75 GB',
            '100 GB',
        ]);
    });

    it('formats fractional values correctly and consistently when arbitrary tick values are supplied', () => {
        const gigabyteBytes = 1024 * 1024 * 1024;
        const scaleResult = computeNiceByteScale(12 * gigabyteBytes);
        expect(scaleResult.formatTick(1.25 * gigabyteBytes)).toBe('1.25 GB');
        expect(scaleResult.formatTick(0)).toBe('0 GB');
    });
});
