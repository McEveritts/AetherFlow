'use client';

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getExpandedRowModel,
  flexRender,
  ColumnDef,
  Row,
  SortingState,
  ExpandedState,
} from '@tanstack/react-table';
import { useVirtualizer } from '@tanstack/react-virtual';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';

interface DataGridProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[];
  data: TData[];
  renderSubComponent?: (props: { row: Row<TData> }) => React.ReactElement;
  getRowCanExpand?: (row: Row<TData>) => boolean;
  className?: string;
  rowHeight?: number;
  initialSorting?: SortingState;
  responsiveRows?: { primaryColumnId: string; actionsColumnId?: string };
}

export function DataGrid<TData, TValue>({
  columns,
  data,
  renderSubComponent,
  getRowCanExpand = () => false,
  className = '',
  rowHeight = 64,
  initialSorting = [],
  responsiveRows,
}: DataGridProps<TData, TValue>) {
  const [sorting, setSorting] = useState<SortingState>(initialSorting);
  const [expanded, setExpanded] = useState<ExpandedState>({});

  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Table is incompatible with React Compiler memoization by design
  const table = useReactTable({
    data,
    columns,
    state: {
      sorting,
      expanded,
    },
    onSortingChange: setSorting,
    onExpandedChange: setExpanded,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    getRowCanExpand,
  });

  const { rows } = table.getRowModel();
  const parentRef = useRef<HTMLDivElement>(null);
  const hasResponsiveRows = Boolean(responsiveRows);
  const getItemKey = useCallback((index: number) => rows[index].id, [rows]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    getItemKey,
    overscan: 10,
  });

  useEffect(() => {
    const container = parentRef.current;
    if (!hasResponsiveRows || !container || typeof ResizeObserver === 'undefined') return;

    let previousWidth = container.getBoundingClientRect().width;
    const observer = new ResizeObserver(() => {
      const nextWidth = container.getBoundingClientRect().width;
      if (nextWidth === previousWidth) return;
      previousWidth = nextWidth;
      virtualizer.measure();
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, [hasResponsiveRows, virtualizer]);

  const virtualItems = virtualizer.getVirtualItems();
  const paddingTop = virtualItems.length > 0 ? virtualItems[0]?.start || 0 : 0;
  const paddingBottom = virtualItems.length > 0
    ? virtualizer.getTotalSize() - (virtualItems[virtualItems.length - 1]?.end || 0)
    : 0;

  return (
    <div
      ref={parentRef}
      data-responsive-grid={responsiveRows ? 'true' : undefined}
      className={`obs-scroller obs-canvas-section overflow-auto min-w-0 max-w-full ${className}`}
      style={{ maxHeight: '600px' }}
    >
      <style>{`
        @media (max-width: 767px) {
          [data-responsive-grid="true"] > .obs-mobile-ledger > thead > tr {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.75rem;
          }
          [data-responsive-grid="true"] > .obs-mobile-ledger > thead > tr > th[data-sortable="false"] {
            display: none !important;
          }
          [data-responsive-grid="true"] > .obs-mobile-ledger > thead > tr > th[data-sortable="true"] {
            display: inline-flex;
            align-items: center;
            flex: 0 0 auto;
            width: auto !important;
            padding: 0;
          }
          [data-responsive-grid="true"] > .obs-mobile-ledger > thead > tr > th[data-sortable="true"] button {
            display: inline-flex;
            align-items: center;
            min-height: 44px;
            min-width: 44px;
            padding: 0.5rem 0.75rem;
            border-radius: 0.75rem;
            background-color: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.1);
          }
        }
      `}</style>
      <table className={`w-full text-left border-collapse min-w-0 ${responsiveRows ? 'obs-mobile-ledger' : ''}`}>
        <thead className="sticky top-0 z-20 bg-slate-900/65 backdrop-blur-md border-b border-white/[0.07] shadow-sm">
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => {
                const canSort = !header.isPlaceholder && header.column.getCanSort();
                return (
                  <th
                    key={header.id}
                    colSpan={header.colSpan}
                    aria-sort={header.column.getIsSorted() === 'asc' ? 'ascending' : header.column.getIsSorted() === 'desc' ? 'descending' : undefined}
                    data-sortable={canSort ? 'true' : 'false'}
                    data-sort-active={Boolean(header.column.getIsSorted())}
                    data-sort-direction={header.column.getIsSorted() || 'none'}
                    className={`p-4 text-xs font-semibold text-slate-300 uppercase tracking-wider group select-none first:pl-6 last:pr-6 ${responsiveRows && !canSort ? 'max-md:!hidden' : ''}`}
                    style={{
                      width: header.getSize() !== 150 ? header.getSize() : 'auto',
                    }}
                  >
                    {header.isPlaceholder ? null : (
                      header.column.getCanSort() ? <button
                        type="button"
                        data-sort-control="true"
                        className="obs-touch-target-standard min-h-[44px] min-w-[44px] flex w-full md:w-auto items-center justify-between md:justify-start gap-2 cursor-pointer hover:text-white transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 rounded"
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        {flexRender(
                          header.column.columnDef.header,
                          header.getContext()
                        )}
                        {{
                          asc: <ArrowUp aria-hidden="true" size={14} className="text-indigo-400" />,
                          desc: <ArrowDown aria-hidden="true" size={14} className="text-indigo-400" />,
                        }[header.column.getIsSorted() as string] ??
                          (header.column.getCanSort() ? (
                            <ArrowUpDown
                              aria-hidden="true"
                              size={14}
                              className="text-slate-500 obs-touch-action-reveal opacity-40 md:opacity-0 md:group-hover:opacity-100 transition-opacity"
                            />
                          ) : null)}
                      </button> : <div>{flexRender(header.column.columnDef.header, header.getContext())}</div>
                    )}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody className="divide-y divide-white/5 text-sm">
          {paddingTop > 0 && (
            <tr data-grid-spacer>
              <td style={{ height: `${paddingTop}px` }} colSpan={columns.length} />
            </tr>
          )}
          {virtualItems.map((virtualRow) => {
            const row = rows[virtualRow.index];
            return (
              <React.Fragment key={row.id}>
                <tr
                  ref={hasResponsiveRows ? virtualizer.measureElement : undefined}
                  data-index={virtualRow.index}
                  className="hover:bg-white/[0.04] transition-colors group"
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      data-primary={responsiveRows?.primaryColumnId === cell.column.id || undefined}
                      data-actions={responsiveRows?.actionsColumnId === cell.column.id || undefined}
                      data-label={typeof cell.column.columnDef.header === 'string' ? cell.column.columnDef.header : cell.column.id}
                      className="p-4 first:pl-6 last:pr-6"
                      style={{
                        width: cell.column.getSize() !== 150 ? cell.column.getSize() : 'auto',
                      }}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
                {/* Expanded Row Content with Framer Motion */}
                <AnimatePresence>
                  {row.getIsExpanded() && renderSubComponent && (
                    <tr className="bg-slate-900/40">
                      <td colSpan={columns.length} className="p-0">
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                          className="overflow-hidden"
                        >
                          {renderSubComponent({ row })}
                        </motion.div>
                      </td>
                    </tr>
                  )}
                </AnimatePresence>
              </React.Fragment>
            );
          })}
          {paddingBottom > 0 && (
            <tr data-grid-spacer>
              <td style={{ height: `${paddingBottom}px` }} colSpan={columns.length} />
            </tr>
          )}
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="p-8 text-center text-slate-500">
                No active rows to display.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
