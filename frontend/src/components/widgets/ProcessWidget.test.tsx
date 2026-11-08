import React from 'react';
import { render, screen } from '@testing-library/react';
import ProcessWidget from '@/components/widgets/ProcessWidget';
import { ProcessInfo } from '@/types/dashboard';

let capturedGridProcesses: ProcessInfo[] = [];
let capturedInitialSorting: { id: string; desc: boolean }[] = [];

jest.mock('@/components/ui/DataGrid', () => ({
    DataGrid: function MockDataGrid({ data, columns, initialSorting }: { data: ProcessInfo[]; initialSorting: { id: string; desc: boolean }[]; columns: Array<{ header: string | (() => React.ReactNode); cell: (info: { getValue: () => unknown }) => React.ReactNode }> }) {
        capturedGridProcesses = data;
        capturedInitialSorting = initialSorting;
        return (
            <div data-testid="mock-data-grid">
                {columns.map((columnItem, columnIndex) => (
                    <div key={columnIndex} data-testid="grid-column-header">
                        {typeof columnItem.header === 'function' ? columnItem.header() : columnItem.header}
                    </div>
                ))}
                {data.map((processItem) => (
                    <div key={processItem.pid} data-testid={`process-row-${processItem.pid}`}>
                        {columns.map((columnItem, columnIndex) => (
                            <div key={columnIndex} data-testid={`cell-${processItem.pid}-${columnIndex}`}>
                                {columnItem.cell({
                                    getValue: () => {
                                        if (columnIndex === 0) return processItem.pid;
                                        if (columnIndex === 1) return processItem.name;
                                        if (columnIndex === 2) return processItem.cpu;
                                        return processItem.mem;
                                    }
                                })}
                            </div>
                        ))}
                    </div>
                ))}
            </div>
        );
    },
}));

jest.mock('swr', () => ({
    __esModule: true,
    default: () => ({ data: undefined }),
}));

describe('ProcessWidget CPU sorting and contract regressions', () => {
    beforeEach(() => {
        capturedGridProcesses = [];
    });

    it('sorts a copy of processes descending by CPU load without mutating the input array', () => {
        const initialProcesses: ProcessInfo[] = Object.freeze([
            Object.freeze({ pid: 101, name: 'plex', cpu: 4.8, mem: 12.5 }),
            Object.freeze({ pid: 102, name: 'sonarr', cpu: 3.4, mem: 8.1 }),
            Object.freeze({ pid: 103, name: 'radarr', cpu: 1.2, mem: 6.4 }),
            Object.freeze({ pid: 104, name: 'sabnzbd', cpu: 0.8, mem: 4.2 }),
            Object.freeze({ pid: 105, name: 'qbittorrent', cpu: 2.1, mem: 15.0 }),
        ]) as unknown as ProcessInfo[];

        render(<ProcessWidget processes={initialProcesses} />);

        expect(screen.getByText('Top Processes')).toBeInTheDocument();
        expect(screen.getByText('5 Tasks')).toBeInTheDocument();

        expect(capturedGridProcesses).toHaveLength(5);
        expect(capturedGridProcesses.map((processItem) => processItem.cpu)).toEqual([
            4.8,
            3.4,
            2.1,
            1.2,
            0.8,
        ]);
        expect(capturedGridProcesses.map((processItem) => processItem.pid)).toEqual([
            101,
            102,
            105,
            103,
            104,
        ]);

        expect(initialProcesses[0].pid).toBe(101);
        expect(initialProcesses[1].pid).toBe(102);
        expect(initialProcesses[2].pid).toBe(103);
        expect(initialProcesses[3].pid).toBe(104);
        expect(initialProcesses[4].pid).toBe(105);
    });

    it('preserves stable input order on equal CPU loads and handles non-finite values safely', () => {
        const tiedProcesses: ProcessInfo[] = [
            { pid: 201, name: 'first-tie', cpu: 2.5, mem: 4.0 },
            { pid: 202, name: 'high-cpu', cpu: 5.0, mem: 2.0 },
            { pid: 203, name: 'second-tie', cpu: 2.5, mem: 5.0 },
            { pid: 204, name: 'invalid-cpu', cpu: NaN, mem: 1.0 },
        ];

        render(<ProcessWidget processes={tiedProcesses} />);

        expect(capturedGridProcesses.map((processItem) => processItem.pid)).toEqual([
            202,
            201,
            203,
            204,
        ]);
    });

    it('displays visible descending ordering cue and readable numeric percentages without tiny progress bars', () => {
        const testProcesses: ProcessInfo[] = [
            { pid: 301, name: 'daemon', cpu: 14.8, mem: 8.5 },
        ];

        const { container } = render(<ProcessWidget processes={testProcesses} />);

        expect(screen.getByText('CPU %')).toBeInTheDocument();
        expect(capturedInitialSorting).toEqual([{ id: 'cpu', desc: true }]);
        expect(screen.queryByText('↓')).not.toBeInTheDocument();

        const cpuValueElement = screen.getByText('14.8%');
        expect(cpuValueElement).toBeInTheDocument();
        expect(cpuValueElement).toHaveClass('text-[13px]');
        expect(cpuValueElement).toHaveClass('text-slate-200');

        const memValueElement = screen.getByText('8.5%');
        expect(memValueElement).toBeInTheDocument();
        expect(memValueElement).toHaveClass('text-[13px]');
        expect(memValueElement).toHaveClass('text-slate-200');
        expect(memValueElement).toHaveClass('font-semibold');

        const pidValueElement = screen.getByText('301');
        expect(pidValueElement).toBeInTheDocument();
        expect(pidValueElement).toHaveClass('text-[13px]');
        expect(pidValueElement).toHaveClass('text-slate-300');

        const processNameElement = screen.getByText('daemon');
        expect(processNameElement).toBeInTheDocument();
        expect(processNameElement).toHaveClass('text-[13px]');
        expect(processNameElement).toHaveClass('text-slate-200');

        const memHeaderElement = screen.getByText('MEM %');
        expect(memHeaderElement).toBeInTheDocument();
        expect(memHeaderElement).toHaveClass('text-slate-300');

        const tinyProgressBarElements = container.querySelectorAll('.w-12.h-1\\.5');
        expect(tinyProgressBarElements).toHaveLength(0);
    });
});
