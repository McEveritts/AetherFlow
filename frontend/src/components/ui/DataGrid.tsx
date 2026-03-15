import React, { useRef, useState } from 'react';
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
}

export function DataGrid<TData, TValue>({
  columns,
  data,
  renderSubComponent,
  getRowCanExpand = () => false,
  className = '',
  rowHeight = 64,
}: DataGridProps<TData, TValue>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});

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

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 5,
  });

  const virtualItems = virtualizer.getVirtualItems();
  const paddingTop = virtualItems.length > 0 ? virtualItems[0]?.start || 0 : 0;
  const paddingBottom = virtualItems.length > 0
    ? virtualizer.getTotalSize() - (virtualItems[virtualItems.length - 1]?.end || 0)
    : 0;

  return (
    <div
      ref={parentRef}
      className={`overflow-auto rounded-3xl border border-white/[0.05] bg-white/[0.02] backdrop-blur-xl shadow-2xl ${className}`}
      style={{ maxHeight: '600px' }}
    >
      <table className="w-full text-left border-collapse">
        <thead className="sticky top-0 z-20 bg-slate-950/80 backdrop-blur-md border-b border-white/10 shadow-sm">
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => {
                return (
                  <th
                    key={header.id}
                    colSpan={header.colSpan}
                    className="p-4 text-xs font-semibold text-slate-400 uppercase tracking-wider group select-none first:pl-6 last:pr-6"
                    style={{
                      width: header.getSize() !== 150 ? header.getSize() : 'auto',
                    }}
                  >
                    {header.isPlaceholder ? null : (
                      <div
                        className={`flex items-center gap-2 ${
                          header.column.getCanSort() ? 'cursor-pointer hover:text-slate-200 transition-colors' : ''
                        }`}
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        {flexRender(
                          header.column.columnDef.header,
                          header.getContext()
                        )}
                        {{
                          asc: <ArrowUp size={14} className="text-indigo-400" />,
                          desc: <ArrowDown size={14} className="text-indigo-400" />,
                        }[header.column.getIsSorted() as string] ??
                          (header.column.getCanSort() ? (
                            <ArrowUpDown
                              size={14}
                              className="text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity"
                            />
                          ) : null)}
                      </div>
                    )}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody className="divide-y divide-white/5 text-sm">
          {paddingTop > 0 && (
            <tr>
              <td style={{ height: `${paddingTop}px` }} colSpan={columns.length} />
            </tr>
          )}
          {virtualItems.map((virtualRow) => {
            const row = rows[virtualRow.index];
            return (
              <React.Fragment key={row.id}>
                <tr className="hover:bg-white/[0.04] transition-colors group">
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
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
                    <tr className="bg-slate-900/30">
                      <td colSpan={columns.length} className="p-0">
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.2, ease: "easeInOut" }}
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
            <tr>
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
