'use client';

import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  Film,
  FolderOutput,
  Hash,
  Loader2,
  Lock,
  Play,
  RefreshCw,
  ShieldAlert,
  X,
} from 'lucide-react';
import {
  extractMcBrowserError,
  formatBytes,
  McBrowserRequestError,
  type McBrowserEntry,
} from '@/lib/mcbrowser';
import type { McBrowserPolicyPermissions } from '@/lib/mcbrowser-workspace';
import {
  MCBROWSER_ACTION_ARCHIVE_FORMAT_DESCRIPTORS,
  MCBROWSER_CHECKSUM_ALGORITHMS,
  detectMcBrowserArchiveFormatFromPath,
  dispatchMcBrowserAction,
  evaluateMcBrowserActionPermissions,
  getMcBrowserArchiveFormatDescriptor,
  type McBrowserActionArchiveFormat,
  type McBrowserActionKind,
  type McBrowserActionResponse,
  type McBrowserChecksumAlgorithm,
} from '@/lib/mcbrowser-actions';

export interface McBrowserActionsProps {
  currentPath?: string;
  selectedPaths?: readonly string[];
  selectedEntries?: readonly McBrowserEntry[];
  permissions?: Partial<McBrowserPolicyPermissions> | null;
  initialAction?: McBrowserActionKind;
  onActionCompleted?: (response: McBrowserActionResponse) => void;
  onRefresh?: () => void;
  onNavigate?: (relativePath: string) => void;
  onClose?: () => void;
  className?: string;
}

const ACTION_TABS: ReadonlyArray<{
  kind: McBrowserActionKind;
  label: string;
  description: string;
}> = [
  {
    kind: 'compute_checksums',
    label: 'Compute Checksums',
    description: 'Compute cryptographic file digests (MD5, SHA-1, SHA-256, SHA-512).',
  },
  {
    kind: 'extract_archive',
    label: 'Extract Archive',
    description: 'Safely unpack an existing archive into an explicit destination directory.',
  },
  {
    kind: 'create_archive',
    label: 'Create Archive',
    description: 'Package explicit relative paths into one of the 9 supported archive formats.',
  },
  {
    kind: 'inspect_media_metadata',
    label: 'Inspect Media Metadata',
    description: 'Read safe media dimensions, MIME type, and subtitle tracks.',
  },
];

function joinRelativeDirAndLeaf(dir: string | undefined, leaf: string): string {
  const cleanedDir = (dir ?? '')
    .trim()
    .replace(/^\/+|\/+$/g, '');
  const cleanedLeaf = leaf.trim().replace(/^\/+|\/+$/g, '');
  if (!cleanedDir) {
    return cleanedLeaf;
  }
  if (!cleanedLeaf) {
    return cleanedDir;
  }
  return `${cleanedDir}/${cleanedLeaf}`;
}

function deriveInitialTargetPaths(
  currentPath?: string,
  selectedPaths?: readonly string[],
  selectedEntries?: readonly McBrowserEntry[],
): string[] {
  const collected: string[] = [];
  if (selectedPaths && selectedPaths.length > 0) {
    for (const p of selectedPaths) {
      const cleaned = p.trim().replace(/^\/+|\/+$/g, '');
      if (cleaned && !collected.includes(cleaned)) {
        collected.push(cleaned);
      }
    }
  }
  if (collected.length === 0 && selectedEntries && selectedEntries.length > 0) {
    for (const entry of selectedEntries) {
      const candidate = entry.path
        ? entry.path.trim().replace(/^\/+|\/+$/g, '')
        : joinRelativeDirAndLeaf(currentPath, entry.name);
      if (candidate && !collected.includes(candidate)) {
        collected.push(candidate);
      }
    }
  }
  return collected;
}

function parseSourcePathsInput(raw: string): string[] {
  return raw
    .split(/[\r\n,]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

export function McBrowserActions({
  currentPath = '',
  selectedPaths,
  selectedEntries,
  permissions,
  initialAction = 'compute_checksums',
  onActionCompleted,
  onRefresh,
  onNavigate,
  onClose,
  className = '',
}: McBrowserActionsProps) {
  const baseId = useId();
  const initialTargets = useMemo(
    () => deriveInitialTargetPaths(currentPath, selectedPaths, selectedEntries),
    [currentPath, selectedPaths, selectedEntries],
  );
  const primaryInitialTarget = initialTargets[0] ?? '';

  const [activeAction, setActiveAction] = useState<McBrowserActionKind>(initialAction);
  const [checksumPath, setChecksumPath] = useState<string>(primaryInitialTarget);
  const [selectedAlgorithms, setSelectedAlgorithms] = useState<McBrowserChecksumAlgorithm[]>([
    'sha256',
  ]);

  const [extractArchivePath, setExtractArchivePath] = useState<string>(primaryInitialTarget);
  const [extractDestinationDir, setExtractDestinationDir] = useState<string>(() =>
    joinRelativeDirAndLeaf(currentPath, 'extracted'),
  );

  const [createSourcePathsText, setCreateSourcePathsText] = useState<string>(() =>
    initialTargets.join('\n'),
  );
  const [createArchiveFormat, setCreateArchiveFormat] =
    useState<McBrowserActionArchiveFormat>('zip');
  const [createDestinationPath, setCreateDestinationPath] = useState<string>(() =>
    joinRelativeDirAndLeaf(currentPath, 'archive.zip'),
  );

  const [inspectMediaPath, setInspectMediaPath] = useState<string>(primaryInitialTarget);

  const [submitting, setSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastResponse, setLastResponse] = useState<McBrowserActionResponse | null>(null);
  const [sessionExpired, setSessionExpired] = useState<boolean>(false);

  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const handleSessionExpired = () => {
      setSessionExpired(true);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
        abortControllerRef.current = null;
      }
      setSubmitting(false);
      setErrorMessage('Your session has expired. Please sign in again to run native actions.');
    };

    window.addEventListener('af:session-expired', handleSessionExpired);
    return () => {
      window.removeEventListener('af:session-expired', handleSessionExpired);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const permissionEval = useMemo(
    () => evaluateMcBrowserActionPermissions(activeAction, permissions),
    [activeAction, permissions],
  );

  const executeEnabled = permissions?.execute === true;

  const handleToggleAlgorithm = useCallback((algo: McBrowserChecksumAlgorithm) => {
    setSelectedAlgorithms((prev) =>
      prev.includes(algo) ? prev.filter((item) => item !== algo) : [...prev, algo],
    );
  }, []);

  const handleFormatChange = useCallback(
    (nextFormat: McBrowserActionArchiveFormat) => {
      setCreateArchiveFormat(nextFormat);
      const descriptor = getMcBrowserArchiveFormatDescriptor(nextFormat);
      setCreateDestinationPath((prev) => {
        const trimmed = prev.trim();
        if (!trimmed) {
          return joinRelativeDirAndLeaf(currentPath, `archive${descriptor.extension}`);
        }
        const existingFmt = detectMcBrowserArchiveFormatFromPath(trimmed);
        if (!existingFmt) {
          return `${trimmed}${descriptor.extension}`;
        }
        const existingDesc = getMcBrowserArchiveFormatDescriptor(existingFmt);
        for (const alias of existingDesc.aliases) {
          const dotted = alias.startsWith('.') ? alias : `.${alias}`;
          if (trimmed.toLowerCase().endsWith(dotted)) {
            return `${trimmed.slice(0, trimmed.length - dotted.length)}${descriptor.extension}`;
          }
        }
        return trimmed;
      });
    },
    [currentPath],
  );

  const handleUseCurrentSelection = useCallback(() => {
    if (initialTargets.length === 0) {
      return;
    }
    const first = initialTargets[0] ?? '';
    if (activeAction === 'compute_checksums') {
      setChecksumPath(first);
    } else if (activeAction === 'extract_archive') {
      setExtractArchivePath(first);
    } else if (activeAction === 'create_archive') {
      setCreateSourcePathsText(initialTargets.join('\n'));
    } else if (activeAction === 'inspect_media_metadata') {
      setInspectMediaPath(first);
    }
  }, [activeAction, initialTargets]);

  const handleCancelRequest = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setSubmitting(false);
  }, []);

  const handleSubmit = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (sessionExpired || !permissionEval.allowed) {
        setErrorMessage(
          permissionEval.reason ?? 'Execution is not permitted for the current policy.',
        );
        return;
      }

      setErrorMessage(null);
      setLastResponse(null);

      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      const controller = new AbortController();
      abortControllerRef.current = controller;
      setSubmitting(true);

      try {
        let response: McBrowserActionResponse;
        if (activeAction === 'compute_checksums') {
          response = await dispatchMcBrowserAction(
            {
              action: 'compute_checksums',
              path: checksumPath,
              algorithms: selectedAlgorithms,
            },
            controller.signal,
          );
        } else if (activeAction === 'extract_archive') {
          response = await dispatchMcBrowserAction(
            {
              action: 'extract_archive',
              archive_path: extractArchivePath,
              destination_dir: extractDestinationDir,
            },
            controller.signal,
          );
        } else if (activeAction === 'create_archive') {
          const sources = parseSourcePathsInput(createSourcePathsText);
          response = await dispatchMcBrowserAction(
            {
              action: 'create_archive',
              source_paths: sources,
              destination_path: createDestinationPath,
              format: createArchiveFormat,
            },
            controller.signal,
          );
        } else {
          response = await dispatchMcBrowserAction(
            {
              action: 'inspect_media_metadata',
              path: inspectMediaPath,
            },
            controller.signal,
          );
        }

        setLastResponse(response);
        onActionCompleted?.(response);
        if (response.action === 'extract_archive' || response.action === 'create_archive') {
          onRefresh?.();
        }
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') {
          return;
        }
        if (err instanceof McBrowserRequestError && err.status === 401) {
          setSessionExpired(true);
        }
        setErrorMessage(extractMcBrowserError(err, 'Failed to execute native action'));
      } finally {
        if (abortControllerRef.current === controller) {
          abortControllerRef.current = null;
          setSubmitting(false);
        }
      }
    },
    [
      activeAction,
      checksumPath,
      createArchiveFormat,
      createDestinationPath,
      createSourcePathsText,
      extractArchivePath,
      extractDestinationDir,
      inspectMediaPath,
      onActionCompleted,
      onRefresh,
      permissionEval.allowed,
      permissionEval.reason,
      selectedAlgorithms,
      sessionExpired,
    ],
  );

  return (
    <section
      aria-label="McBrowser Native Actions"
      data-testid="mcbrowser-actions-panel"
      className={`obs-canvas-section py-4 text-slate-100 ${className}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] pb-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/15 text-indigo-400">
            <Archive className="h-4 w-4" aria-hidden="true" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Native File &amp; Archive Actions
            </h2>
            <p className="text-xs text-slate-400">
              Safe typed native operations with explicit relative paths and policy gating.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span
            data-testid="mcbrowser-actions-execute-badge"
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${
              executeEnabled
                ? 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                : 'border border-amber-500/30 bg-amber-500/10 text-amber-300'
            }`}
          >
            <Lock className="h-3 w-3" aria-hidden="true" />
            {executeEnabled ? 'Execute: Allowed' : 'Execute: Off (Default Gate)'}
          </span>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              aria-label="Close native actions panel"
              className="rounded-lg border border-slate-700 bg-slate-800/80 p-1.5 text-slate-300 hover:bg-slate-700 hover:text-white"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      {!executeEnabled && (
        <div
          role="alert"
          data-testid="mcbrowser-actions-execute-gate"
          className="mt-3 flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-950/40 p-3 text-xs text-amber-200"
        >
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          <div>
            <p className="font-semibold">Execute permission is disabled by default</p>
            <p className="mt-0.5 text-amber-200/90">
              Native actions require the <code className="font-mono">execute</code> policy
              permission to be explicitly enabled by an administrator before dispatching.
            </p>
          </div>
        </div>
      )}

      {executeEnabled && !permissionEval.allowed && (
        <div
          role="alert"
          data-testid="mcbrowser-actions-secondary-gate"
          className="mt-3 flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-950/40 p-3 text-xs text-amber-200"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          <div>
            <p className="font-semibold">Additional permission required for {activeAction}</p>
            <p className="mt-0.5 text-amber-200/90">{permissionEval.reason}</p>
          </div>
        </div>
      )}

      <div
        role="tablist"
        aria-label="Native action variants"
        className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4"
      >
        {ACTION_TABS.map((tab) => {
          const isSelected = activeAction === tab.kind;
          return (
            <button
              key={tab.kind}
              type="button"
              role="tab"
              aria-selected={isSelected}
              data-testid={`mcbrowser-action-tab-${tab.kind}`}
              onClick={() => {
                setActiveAction(tab.kind);
                setErrorMessage(null);
              }}
              className={`flex flex-col items-start rounded-lg border px-3 py-2 text-left text-xs transition ${
                isSelected
                  ? 'border-indigo-500 bg-indigo-500/15 text-indigo-200'
                  : 'border-slate-800 bg-slate-950/60 text-slate-300 hover:border-slate-700 hover:bg-slate-800/60'
              }`}
            >
              <span className="font-semibold">{tab.label}</span>
            </button>
          );
        })}
      </div>

      <form onSubmit={handleSubmit} className="mt-4 space-y-4" noValidate>
        {initialTargets.length > 0 && (
          <div className="flex items-center justify-between border-y border-white/[0.07] py-2 text-xs text-slate-300">
            <span>
              Workspace selection available ({initialTargets.length}{' '}
              {initialTargets.length === 1 ? 'item' : 'items'})
            </span>
            <button
              type="button"
              onClick={handleUseCurrentSelection}
              disabled={submitting || sessionExpired}
              className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-50"
            >
              Use Selected Path(s)
            </button>
          </div>
        )}

        {activeAction === 'compute_checksums' && (
          <div className="space-y-3" data-testid="mcbrowser-action-form-compute_checksums">
            <div>
              <label
                htmlFor={`${baseId}-checksum-path`}
                className="block text-xs font-medium text-slate-300"
              >
                Source File Path (Relative)
              </label>
              <input
                id={`${baseId}-checksum-path`}
                type="text"
                value={checksumPath}
                onChange={(e) => setChecksumPath(e.target.value)}
                placeholder="e.g. releases/bundle.tar.gz"
                disabled={submitting || sessionExpired}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>

            <fieldset>
              <legend className="text-xs font-medium text-slate-300">
                Checksum Algorithms
              </legend>
              <div className="mt-1.5 flex flex-wrap gap-3">
                {MCBROWSER_CHECKSUM_ALGORITHMS.map((algo) => {
                  const checked = selectedAlgorithms.includes(algo);
                  return (
                    <label
                      key={algo}
                      className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200"
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => handleToggleAlgorithm(algo)}
                        disabled={submitting || sessionExpired}
                        aria-label={`Algorithm ${algo.toUpperCase()}`}
                        className="rounded border-slate-700 bg-slate-900 text-indigo-500"
                      />
                      <span className="font-mono uppercase">{algo}</span>
                    </label>
                  );
                })}
              </div>
            </fieldset>
          </div>
        )}

        {activeAction === 'extract_archive' && (
          <div className="space-y-3" data-testid="mcbrowser-action-form-extract_archive">
            <div>
              <label
                htmlFor={`${baseId}-extract-source`}
                className="block text-xs font-medium text-slate-300"
              >
                Source Archive Path (Relative)
              </label>
              <input
                id={`${baseId}-extract-source`}
                type="text"
                value={extractArchivePath}
                onChange={(e) => setExtractArchivePath(e.target.value)}
                placeholder="e.g. backups/snapshot.tar.zst"
                disabled={submitting || sessionExpired}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>

            <div>
              <label
                htmlFor={`${baseId}-extract-destination`}
                className="block text-xs font-medium text-slate-300"
              >
                Destination Directory Path (Relative)
              </label>
              <input
                id={`${baseId}-extract-destination`}
                type="text"
                value={extractDestinationDir}
                onChange={(e) => setExtractDestinationDir(e.target.value)}
                placeholder="e.g. backups/restored-snapshot"
                disabled={submitting || sessionExpired}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </div>
        )}

        {activeAction === 'create_archive' && (
          <div className="space-y-3" data-testid="mcbrowser-action-form-create_archive">
            <div>
              <label
                htmlFor={`${baseId}-create-sources`}
                className="block text-xs font-medium text-slate-300"
              >
                Source Paths (Relative, one per line or comma-separated)
              </label>
              <textarea
                id={`${baseId}-create-sources`}
                rows={3}
                value={createSourcePathsText}
                onChange={(e) => setCreateSourcePathsText(e.target.value)}
                placeholder={'src/index.ts\nREADME.md'}
                disabled={submitting || sessionExpired}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label
                  htmlFor={`${baseId}-create-format`}
                  className="block text-xs font-medium text-slate-300"
                >
                  Archive Format
                </label>
                <select
                  id={`${baseId}-create-format`}
                  value={createArchiveFormat}
                  onChange={(e) =>
                    handleFormatChange(e.target.value as McBrowserActionArchiveFormat)
                  }
                  disabled={submitting || sessionExpired}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 focus:border-indigo-500 focus:outline-none"
                >
                  {MCBROWSER_ACTION_ARCHIVE_FORMAT_DESCRIPTORS.map((desc) => (
                    <option key={desc.format} value={desc.format}>
                      {desc.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label
                  htmlFor={`${baseId}-create-destination`}
                  className="block text-xs font-medium text-slate-300"
                >
                  Destination Archive Path (Relative)
                </label>
                <input
                  id={`${baseId}-create-destination`}
                  type="text"
                  value={createDestinationPath}
                  onChange={(e) => setCreateDestinationPath(e.target.value)}
                  placeholder="e.g. exports/release.zip"
                  disabled={submitting || sessionExpired}
                  className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none"
                />
              </div>
            </div>
          </div>
        )}

        {activeAction === 'inspect_media_metadata' && (
          <div
            className="space-y-3"
            data-testid="mcbrowser-action-form-inspect_media_metadata"
          >
            <div>
              <label
                htmlFor={`${baseId}-inspect-path`}
                className="block text-xs font-medium text-slate-300"
              >
                Source Media Path (Relative)
              </label>
              <input
                id={`${baseId}-inspect-path`}
                type="text"
                value={inspectMediaPath}
                onChange={(e) => setInspectMediaPath(e.target.value)}
                placeholder="e.g. media/recordings/demo.mp4"
                disabled={submitting || sessionExpired}
                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </div>
        )}

        {errorMessage && (
          <div
            role="alert"
            data-testid="mcbrowser-actions-error"
            className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-950/40 p-3 text-xs text-rose-200"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
            <span>{errorMessage}</span>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-1">
          {submitting && (
            <button
              type="button"
              onClick={handleCancelRequest}
              data-testid="mcbrowser-actions-cancel"
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
            >
              Cancel
            </button>
          )}
          <button
            type="submit"
            data-testid="mcbrowser-actions-submit"
            disabled={submitting || sessionExpired || !permissionEval.allowed}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                Running Action...
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5" aria-hidden="true" />
                Run Native Action
              </>
            )}
          </button>
        </div>
      </form>

      {lastResponse && (
        <div
          data-testid="mcbrowser-actions-result"
          className="mt-4 rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3 text-xs text-slate-200"
        >
          <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2">
            <div className="flex items-center gap-1.5 font-semibold text-emerald-300">
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
              <span>Action Completed: {lastResponse.action}</span>
            </div>
            {onRefresh && (
              <button
                type="button"
                onClick={onRefresh}
                className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700"
              >
                <RefreshCw className="h-3 w-3" aria-hidden="true" />
                Refresh Directory
              </button>
            )}
          </div>

          {lastResponse.action === 'compute_checksums' && (
            <div className="mt-2.5 space-y-2">
              <div className="flex flex-wrap gap-4 text-slate-300">
                <span>
                  Path: <code className="font-mono text-slate-100">{lastResponse.path}</code>
                </span>
                <span>Size: {formatBytes(lastResponse.size)}</span>
              </div>
              <dl className="space-y-1.5">
                {Object.entries(lastResponse.checksums).map(([algo, digest]) => (
                  <div
                    key={algo}
                    className="flex flex-col rounded border border-slate-800 bg-slate-950/70 px-2.5 py-1.5 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <dt className="flex items-center gap-1 font-mono font-semibold uppercase text-indigo-300">
                      <Hash className="h-3 w-3" aria-hidden="true" />
                      {algo}
                    </dt>
                    <dd className="break-all font-mono text-slate-100">{digest}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}

          {lastResponse.action === 'extract_archive' && (
            <div className="mt-2.5 space-y-2">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <div>
                  Source Archive:{' '}
                  <code className="font-mono text-slate-100">{lastResponse.archive_path}</code>
                </div>
                <div>
                  Destination:{' '}
                  <code className="font-mono text-slate-100">
                    {lastResponse.destination_dir}
                  </code>
                </div>
                <div>Format: {lastResponse.format}</div>
                <div>
                  Extracted: {lastResponse.extracted_files} files,{' '}
                  {lastResponse.extracted_directories} directories (
                  {formatBytes(lastResponse.extracted_bytes)})
                </div>
              </div>
              {onNavigate && (
                <div>
                  <button
                    type="button"
                    onClick={() => onNavigate(lastResponse.destination_dir)}
                    className="inline-flex items-center gap-1 rounded border border-indigo-500/40 bg-indigo-500/15 px-2.5 py-1 text-xs font-medium text-indigo-200 hover:bg-indigo-500/25"
                  >
                    <FolderOutput className="h-3.5 w-3.5" aria-hidden="true" />
                    Open Extracted Directory
                  </button>
                </div>
              )}
            </div>
          )}

          {lastResponse.action === 'create_archive' && (
            <div className="mt-2.5 space-y-2">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                <div>
                  Archive Path:{' '}
                  <code className="font-mono text-slate-100">
                    {lastResponse.destination_path}
                  </code>
                </div>
                <div>Format: {lastResponse.format}</div>
                <div>
                  Entries: {lastResponse.entry_count} ({formatBytes(lastResponse.archive_bytes)})
                </div>
              </div>
            </div>
          )}

          {lastResponse.action === 'inspect_media_metadata' && (
            <div className="mt-2.5 space-y-2">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <div className="flex items-center gap-1.5">
                  <Film className="h-3.5 w-3.5 text-indigo-400" aria-hidden="true" />
                  <span>
                    Name: <strong className="text-slate-100">{lastResponse.name}</strong> (
                    {lastResponse.kind})
                  </span>
                </div>
                <div>MIME Type: {lastResponse.content_type ?? 'unknown'}</div>
                <div>Size: {formatBytes(lastResponse.size)}</div>
                <div>
                  Resolution:{' '}
                  {lastResponse.resolution
                    ? `${lastResponse.resolution.width}x${lastResponse.resolution.height}`
                    : 'N/A'}
                </div>
              </div>
              {lastResponse.subtitles.length > 0 && (
                <div>
                  <p className="font-medium text-slate-300">
                    Subtitle Tracks ({lastResponse.subtitles.length}):
                  </p>
                  <ul className="mt-1 space-y-1">
                    {lastResponse.subtitles.map((track) => (
                      <li
                        key={track.path}
                        className="rounded border border-slate-800 bg-slate-950/60 px-2 py-1 font-mono text-xs"
                      >
                        {track.label} ({track.format}) — {track.path}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

export default McBrowserActions;
