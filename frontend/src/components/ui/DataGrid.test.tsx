import React from 'react';
import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useVirtualizer } from '@tanstack/react-virtual';
import { DataGrid } from './DataGrid';
import type { ColumnDef } from '@tanstack/react-table';

const mockMeasureElement = jest.fn();
const mockMeasure = jest.fn();

jest.mock('@tanstack/react-virtual', () => ({
    useVirtualizer: jest.fn(({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
        getVirtualItems: () => Array.from({ length: count }, (_unused, index) => ({
            index,
            start: index * estimateSize(),
            end: (index + 1) * estimateSize(),
        })),
        getTotalSize: () => count * estimateSize(),
        measureElement: mockMeasureElement,
        measure: mockMeasure,
    })),
}));

interface TestRow {
    name: string;
    cpu: number;
}

const columns: ColumnDef<TestRow, unknown>[] = [
    { accessorKey: 'name', header: 'Name' },
    { accessorKey: 'cpu', header: 'CPU %' },
];

it('keeps the scrollable table embedded in the page canvas', () => {
    render(<DataGrid columns={columns} data={[]} />);

    const container = screen.getByRole('table').parentElement;
    expect(container).toHaveClass('obs-canvas-section', 'overflow-auto', 'min-w-0', 'max-w-full');
    expect(container).not.toHaveClass('rounded-2xl', 'shadow-sm', 'backdrop-blur-xl');
    expect(screen.getByText('No active rows to display.')).toBeInTheDocument();
});

it('offers keyboard sorting with a single indicator and truthful sort state', async () => {
    const user = userEvent.setup();
    render(<DataGrid columns={columns} data={[{ name: 'first', cpu: 10 }, { name: 'second', cpu: 20 }]} initialSorting={[{ id: 'cpu', desc: true }]} />);
    const header = screen.getByRole('columnheader', { name: 'CPU %' });
    expect(header.closest('thead')).toHaveClass('bg-slate-900/65', 'backdrop-blur-md', 'border-white/[0.07]');
    const button = within(header).getByRole('button', { name: 'CPU %' });
    expect(header).toHaveAttribute('aria-sort', 'descending');
    expect(header.querySelectorAll('svg')).toHaveLength(1);
    button.focus();
    await user.keyboard('{Enter}');
    expect(header).not.toHaveAttribute('aria-sort', 'descending');
    expect(header.querySelectorAll('svg')).toHaveLength(1);
    const stateAfterEnter = header.getAttribute('aria-sort');
    await user.keyboard(' ');
    expect(header.getAttribute('aria-sort')).not.toBe(stateAfterEnter);
    expect(header.querySelectorAll('svg')).toHaveLength(1);
});

it('measures responsive rows and invalidates cached heights after width changes', async () => {
    const originalResizeObserver = globalThis.ResizeObserver;
    let notifyResize: ResizeObserverCallback = () => undefined;
    const disconnect = jest.fn();
    globalThis.ResizeObserver = jest.fn((callback: ResizeObserverCallback) => {
        notifyResize = callback;
        return { observe: jest.fn(), unobserve: jest.fn(), disconnect };
    }) as unknown as typeof ResizeObserver;
    mockMeasure.mockClear();
    mockMeasureElement.mockClear();

    try {
        const user = userEvent.setup();
        const { unmount } = render(
            <DataGrid columns={columns} data={[{ name: 'first', cpu: 10 }, { name: 'second', cpu: 20 }]} responsiveRows={{ primaryColumnId: 'name' }} />
        );
        const table = screen.getByRole('table');
        expect(table).toHaveClass('obs-mobile-ledger');
        const firstRow = screen.getByRole('cell', { name: 'first' }).closest('tr');
        expect(firstRow).toHaveAttribute('data-index', '0');
        expect(mockMeasureElement).toHaveBeenCalledWith(firstRow);
        expect(screen.getByRole('cell', { name: 'first' })).toHaveAttribute('data-primary', 'true');
        expect(screen.getByRole('cell', { name: '10' })).toHaveAttribute('data-label', 'CPU %');

        const firstKey = jest.mocked(useVirtualizer).mock.calls.at(-1)?.[0].getItemKey?.(0);
        await user.click(screen.getByRole('button', { name: 'CPU %' }));
        const sortedKey = jest.mocked(useVirtualizer).mock.calls.at(-1)?.[0].getItemKey?.(0);
        expect(sortedKey).not.toBe(firstKey);

        const container = table.parentElement as HTMLDivElement;
        container.getBoundingClientRect = () => ({ width: 358 }) as DOMRect;
        act(() => notifyResize([], {} as ResizeObserver));
        expect(mockMeasure).toHaveBeenCalledTimes(1);
        act(() => notifyResize([], {} as ResizeObserver));
        expect(mockMeasure).toHaveBeenCalledTimes(1);
        container.getBoundingClientRect = () => ({ width: 900 }) as DOMRect;
        act(() => notifyResize([], {} as ResizeObserver));
        expect(mockMeasure).toHaveBeenCalledTimes(2);
        unmount();
        expect(disconnect).toHaveBeenCalledTimes(jest.mocked(globalThis.ResizeObserver).mock.calls.length);
    } finally {
        globalThis.ResizeObserver = originalResizeObserver;
    }
});

it('configures mobile sort layout flags and preserves sorting interactions on sortable columns', async () => {
    const user = userEvent.setup();
    const mixedColumns: ColumnDef<TestRow, unknown>[] = [
        { accessorKey: 'name', header: 'Name', enableSorting: false },
        { accessorKey: 'cpu', header: 'CPU %' },
    ];
    render(
        <DataGrid
            columns={mixedColumns}
            data={[{ name: 'first', cpu: 10 }, { name: 'second', cpu: 20 }]}
            responsiveRows={{ primaryColumnId: 'name' }}
        />
    );

    const nonSortableHeader = screen.getByRole('columnheader', { name: 'Name' });
    expect(nonSortableHeader.closest('table')?.parentElement).toHaveAttribute('data-responsive-grid', 'true');
    expect(nonSortableHeader).toHaveAttribute('data-sortable', 'false');
    expect(nonSortableHeader).toHaveClass('max-md:!hidden');

    const sortableHeader = screen.getByRole('columnheader', { name: 'CPU %' });
    expect(sortableHeader).toHaveAttribute('data-sortable', 'true');
    expect(sortableHeader).not.toHaveClass('max-md:!hidden');

    const sortControlButton = within(sortableHeader).getByRole('button', { name: 'CPU %' });
    expect(sortControlButton).toHaveAttribute('data-sort-control', 'true');
    expect(sortControlButton).toHaveClass('obs-touch-target-standard', 'min-h-[44px]', 'min-w-[44px]');

    await user.click(sortControlButton);
    expect(sortableHeader).toHaveAttribute('aria-sort', 'descending');
    expect(sortableHeader).toHaveAttribute('data-sort-active', 'true');
    expect(sortableHeader).toHaveAttribute('data-sort-direction', 'desc');
});
