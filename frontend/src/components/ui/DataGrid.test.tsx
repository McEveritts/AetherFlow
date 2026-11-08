import React from 'react';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DataGrid } from './DataGrid';
import type { ColumnDef } from '@tanstack/react-table';

interface TestRow {
    name: string;
    cpu: number;
}

const columns: ColumnDef<TestRow, unknown>[] = [
    { accessorKey: 'name', header: 'Name' },
    { accessorKey: 'cpu', header: 'CPU %' },
];

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
