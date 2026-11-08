'use client';

import React, { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import {
    AlertTriangle,
    ArrowUp,
    Clock,
    Download,
    Eye,
    EyeOff,
    FileText,
    Folder,
    FolderOpen,
    Lock,
    RefreshCw,
    Search,
    ShieldAlert,
    Unlock,
} from 'lucide-react';
import {
    buildShareBreadcrumbs,
    downloadPublicShareFile,
    extractPublicShareErrorMessage,
    fetchPublicShareMetadata,
    formatShareBytes,
    formatShareTimestamp,
    getParentSharePath,
    isShareExpiredAt,
    listPublicShareEntries,
    normalizeShareSubPath,
    PublicShareEntry,
    PublicShareError,
    PublicShareMetadata,
    unlockPublicShare,
    validatePublicShareToken,
} from '@/lib/mcbrowser-share';

type SharePagePhase =
    | 'invalid-token'
    | 'loading-metadata'
    | 'locked'
    | 'ready'
    | 'expired-or-revoked'
    | 'error';

interface PublicShareViewProps {
    initialToken?: string | null;
}

function PublicShareView({ initialToken }: PublicShareViewProps) {
    const searchParams = useSearchParams();

    const rawToken = useMemo(() => {
        if (typeof initialToken === 'string') {
            return initialToken;
        }
        const fromHook = searchParams?.get('token');
        if (fromHook) {
            return fromHook;
        }
        if (typeof window !== 'undefined') {
            return new URLSearchParams(window.location.search).get('token') ?? '';
        }
        return '';
    }, [initialToken, searchParams]);

    const validatedTokenResult = useMemo(() => {
        try {
            return {
                token: validatePublicShareToken(rawToken),
                error: null as string | null,
            };
        } catch (err) {
            return {
                token: null as string | null,
                error: extractPublicShareErrorMessage(
                    err,
                    'Invalid or missing share link token.'
                ),
            };
        }
    }, [rawToken]);

    const token = validatedTokenResult.token;

    const [phase, setPhase] = useState<SharePagePhase>(
        token ? 'loading-metadata' : 'invalid-token'
    );
    const [metadata, setMetadata] = useState<PublicShareMetadata | null>(null);
    const [accessToken, setAccessToken] = useState<string | null>(null);
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [isUnlocking, setIsUnlocking] = useState(false);
    const [unlockError, setUnlockError] = useState<string | null>(null);

    const [currentPath, setCurrentPath] = useState('');
    const [entries, setEntries] = useState<PublicShareEntry[]>([]);
    const [isLoadingEntries, setIsLoadingEntries] = useState(false);
    const [filterQuery, setFilterQuery] = useState('');

    const [pageErrorMessage, setPageErrorMessage] = useState<string | null>(null);
    const [pageErrorForbidden, setPageErrorForbidden] = useState(false);
    const [actionError, setActionError] = useState<string | null>(null);
    const [downloadingTarget, setDownloadingTarget] = useState<string | null>(null);

    const requestGenRef = useRef(0);
    const metadataRef = useRef<PublicShareMetadata | null>(null);
    const accessTokenRef = useRef<string | null>(null);

    useEffect(() => {
        metadataRef.current = metadata;
    }, [metadata]);

    useEffect(() => {
        accessTokenRef.current = accessToken;
    }, [accessToken]);

    const checkCurrentMetadataExpiry = useCallback((meta: PublicShareMetadata | null): boolean => {
        if (meta && isShareExpiredAt(meta.expires_at)) {
            setPhase('expired-or-revoked');
            setPageErrorMessage(
                'This shared link has expired and is no longer available.'
            );
            return true;
        }
        return false;
    }, []);

    const loadEntries = useCallback(
        async (
            targetToken: string,
            targetRelativePath: string,
            overrideAccessToken?: string | null,
            metaSnapshot?: PublicShareMetadata | null
        ) => {
            const activeMeta = metaSnapshot !== undefined ? metaSnapshot : metadataRef.current;
            if (checkCurrentMetadataExpiry(activeMeta)) {
                return;
            }

            let normalizedPath = '';
            try {
                normalizedPath = normalizeShareSubPath(targetRelativePath);
            } catch (err) {
                setActionError(
                    extractPublicShareErrorMessage(
                        err,
                        'Requested path is outside the shared scope.'
                    )
                );
                return;
            }

            setIsLoadingEntries(true);
            setActionError(null);

            try {
                const effectiveAccessToken =
                    overrideAccessToken !== undefined
                        ? overrideAccessToken
                        : accessTokenRef.current;
                const resp = await listPublicShareEntries(targetToken, normalizedPath, {
                    accessToken: effectiveAccessToken,
                });
                setCurrentPath(resp.path);
                setEntries(resp.entries);
                setPhase('ready');
            } catch (err) {
                if (err instanceof PublicShareError) {
                    if (err.isUnavailableOrExpired) {
                        setPhase('expired-or-revoked');
                        setPageErrorMessage(
                            err.message ||
                                'This shared link was not found, has been revoked, or has expired.'
                        );
                        return;
                    }
                    if (err.isUnauthorized) {
                        accessTokenRef.current = null;
                        setAccessToken(null);
                        setPhase('locked');
                        setUnlockError(
                            err.message ||
                                'Password authentication is required to access this share.'
                        );
                        return;
                    }
                    if (err.isForbidden) {
                        setActionError(
                            err.message || 'Access to the requested path is not permitted.'
                        );
                        return;
                    }
                }
                setActionError(
                    extractPublicShareErrorMessage(err, 'Failed to load shared entries.')
                );
            } finally {
                setIsLoadingEntries(false);
            }
        },
        [checkCurrentMetadataExpiry]
    );

    const initializeShare = useCallback(async () => {
        if (!token) {
            setPhase('invalid-token');
            metadataRef.current = null;
            setMetadata(null);
            setEntries([]);
            setCurrentPath('');
            return;
        }

        const gen = ++requestGenRef.current;
        setPhase('loading-metadata');
        setPageErrorMessage(null);
        setPageErrorForbidden(false);
        setActionError(null);
        setUnlockError(null);
        setEntries([]);
        setCurrentPath('');
        setFilterQuery('');

        try {
            const meta = await fetchPublicShareMetadata(token);
            if (gen !== requestGenRef.current) return;

            metadataRef.current = meta;
            setMetadata(meta);

            if (isShareExpiredAt(meta.expires_at)) {
                setPhase('expired-or-revoked');
                setPageErrorMessage(
                    'This shared link has expired and is no longer available.'
                );
                return;
            }

            if (meta.password_required) {
                accessTokenRef.current = null;
                setAccessToken(null);
                setPhase('locked');
                return;
            }

            await loadEntries(token, '', null, meta);
        } catch (err) {
            if (gen !== requestGenRef.current) return;

            if (err instanceof PublicShareError) {
                if (err.isUnavailableOrExpired) {
                    setPhase('expired-or-revoked');
                    setPageErrorMessage(
                        err.message ||
                            'This shared link was not found, has been revoked by its owner, or has expired.'
                    );
                    return;
                }
                if (err.isForbidden) {
                    setPhase('error');
                    setPageErrorForbidden(true);
                    setPageErrorMessage(
                        err.message || 'Access to this shared item is not permitted.'
                    );
                    return;
                }
            }

            setPhase('error');
            setPageErrorForbidden(false);
            setPageErrorMessage(
                extractPublicShareErrorMessage(
                    err,
                    'Unable to load shared link metadata.'
                )
            );
        }
    }, [loadEntries, token]);

    useEffect(() => {
        void initializeShare();
    }, [initializeShare]);

    const handleUnlockSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (!token) return;
        if (checkCurrentMetadataExpiry(metadata)) return;

        if (!password) {
            setUnlockError('Please enter the share password.');
            return;
        }

        setIsUnlocking(true);
        setUnlockError(null);
        setActionError(null);

        try {
            const unlockResp = await unlockPublicShare(token, password);
            const mintedToken = unlockResp.access_token || null;
            setAccessToken(mintedToken);
            setPassword('');
            await loadEntries(token, currentPath, mintedToken, metadata);
        } catch (err) {
            if (err instanceof PublicShareError) {
                if (err.isUnavailableOrExpired) {
                    setPhase('expired-or-revoked');
                    setPageErrorMessage(
                        err.message ||
                            'This shared link was not found, has been revoked, or has expired.'
                    );
                    return;
                }
                if (err.isRateLimited) {
                    setUnlockError(
                        err.message ||
                            'Too many failed password attempts. Please wait a moment and try again.'
                    );
                    return;
                }
                if (err.isPasswordInvalid || err.isUnauthorized) {
                    setUnlockError(
                        err.message || 'Invalid share password. Please try again.'
                    );
                    return;
                }
            }
            setUnlockError(
                extractPublicShareErrorMessage(err, 'Failed to unlock share.')
            );
        } finally {
            setIsUnlocking(false);
        }
    };

    const handleDownload = async (relativePath: string, fallbackFilename: string) => {
        if (!token || !metadata) return;
        if (checkCurrentMetadataExpiry(metadata)) return;

        if (!metadata.allow_download) {
            setActionError('Downloads are disabled for this share.');
            return;
        }

        const targetKey = relativePath || '__single_file__';
        setDownloadingTarget(targetKey);
        setActionError(null);

        try {
            await downloadPublicShareFile(token, relativePath, {
                fallbackFilename,
                accessToken,
            });
        } catch (err) {
            if (err instanceof PublicShareError) {
                if (err.isUnavailableOrExpired) {
                    setPhase('expired-or-revoked');
                    setPageErrorMessage(
                        err.message ||
                            'This shared item is no longer available or has expired.'
                    );
                    return;
                }
                if (err.isUnauthorized) {
                    setAccessToken(null);
                    setPhase('locked');
                    setUnlockError(
                        err.message ||
                            'Your share unlock session has expired. Please enter the password again.'
                    );
                    return;
                }
                if (err.isForbidden) {
                    setActionError(
                        err.message || 'Download of the requested file is not permitted.'
                    );
                    return;
                }
            }
            setActionError(
                extractPublicShareErrorMessage(err, 'Failed to download shared file.')
            );
        } finally {
            setDownloadingTarget(null);
        }
    };

    const handleNavigateDirectory = (targetPath: string) => {
        if (!token || !metadata?.is_directory) return;
        setFilterQuery('');
        void loadEntries(token, targetPath);
    };

    const breadcrumbs = useMemo(() => {
        if (!metadata?.is_directory) return [];
        return buildShareBreadcrumbs(metadata.name, currentPath);
    }, [currentPath, metadata]);

    const sortedFilteredEntries = useMemo(() => {
        const query = filterQuery.trim().toLowerCase();
        const filtered = query
            ? entries.filter((entry) => entry.name.toLowerCase().includes(query))
            : entries;

        return [...filtered].sort((a, b) => {
            if (a.kind !== b.kind) {
                return a.kind === 'directory' ? -1 : 1;
            }
            return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
        });
    }, [entries, filterQuery]);

    const directoryCount = useMemo(
        () => sortedFilteredEntries.filter((e) => e.kind === 'directory').length,
        [sortedFilteredEntries]
    );
    const fileCount = useMemo(
        () => sortedFilteredEntries.filter((e) => e.kind === 'file').length,
        [sortedFilteredEntries]
    );

    const singleFileEntry = useMemo(() => {
        if (!metadata || metadata.is_directory) return null;
        return entries[0] ?? null;
    }, [entries, metadata]);

    return (
        <main
            aria-label="Public shared content"
            className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center px-4 py-10 sm:px-6 lg:px-8"
        >
            <div className="w-full max-w-4xl space-y-6">
                {/* Brand & Security Banner */}
                <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                    <div className="flex items-center gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
                            <FolderOpen className="h-5 w-5" aria-hidden="true" />
                        </div>
                        <div>
                            <p className="text-xs font-semibold uppercase tracking-wider text-indigo-400">
                                AetherFlow McBrowser
                            </p>
                            <h1 className="text-lg font-semibold text-slate-100">
                                Public Share Access
                            </h1>
                        </div>
                    </div>
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-900 border border-slate-800 px-3 py-1 text-xs font-medium text-slate-300">
                        <Lock className="h-3.5 w-3.5 text-indigo-400" aria-hidden="true" />
                        Scoped Read-Only Link
                    </span>
                </header>

                {/* 1. Invalid or Missing Token State */}
                {phase === 'invalid-token' && (
                    <section
                        role="alert"
                        aria-labelledby="share-invalid-heading"
                        className="rounded-2xl border border-amber-500/30 bg-slate-900/90 p-6 sm:p-8 shadow-xl"
                    >
                        <div className="flex items-start gap-4">
                            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-amber-500/15 text-amber-400">
                                <AlertTriangle className="h-6 w-6" aria-hidden="true" />
                            </div>
                            <div className="space-y-2">
                                <h2
                                    id="share-invalid-heading"
                                    className="text-lg font-semibold text-slate-100"
                                >
                                    Invalid or Missing Share Link
                                </h2>
                                <p className="text-sm text-slate-300">
                                    {validatedTokenResult.error ||
                                        'A valid share token is required to view this item. Please check that you copied the full /share?token=... address.'}
                                </p>
                            </div>
                        </div>
                    </section>
                )}

                {/* 2. Loading Metadata State */}
                {phase === 'loading-metadata' && (
                    <section
                        role="status"
                        aria-live="polite"
                        aria-busy="true"
                        className="rounded-2xl border border-slate-800 bg-slate-900/80 p-8 text-center shadow-xl"
                    >
                        <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-4 border-indigo-500/20 border-t-indigo-500" />
                        <p className="text-sm font-medium text-slate-200">
                            Loading shared link...
                        </p>
                        <p className="mt-1 text-xs text-slate-400">
                            Verifying share status and permissions
                        </p>
                    </section>
                )}

                {/* 3. Expired or Revoked State */}
                {phase === 'expired-or-revoked' && (
                    <section
                        role="alert"
                        aria-labelledby="share-expired-heading"
                        className="rounded-2xl border border-rose-500/30 bg-slate-900/90 p-6 sm:p-8 shadow-xl"
                    >
                        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                            <div className="flex items-start gap-4">
                                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-rose-500/15 text-rose-400">
                                    <Clock className="h-6 w-6" aria-hidden="true" />
                                </div>
                                <div className="space-y-2">
                                    <h2
                                        id="share-expired-heading"
                                        className="text-lg font-semibold text-slate-100"
                                    >
                                        Share Unavailable or Expired
                                    </h2>
                                    <p className="text-sm text-slate-300">
                                        {pageErrorMessage ||
                                            'This shared link was not found, has been revoked by its owner, or has expired.'}
                                    </p>
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={() => void initializeShare()}
                                className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                            >
                                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                                Check Again
                            </button>
                        </div>
                    </section>
                )}

                {/* 4. Generic / Forbidden Error State */}
                {phase === 'error' && (
                    <section
                        role="alert"
                        aria-labelledby="share-error-heading"
                        className="rounded-2xl border border-rose-500/30 bg-slate-900/90 p-6 sm:p-8 shadow-xl"
                    >
                        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                            <div className="flex items-start gap-4">
                                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-rose-500/15 text-rose-400">
                                    <ShieldAlert className="h-6 w-6" aria-hidden="true" />
                                </div>
                                <div className="space-y-2">
                                    <h2
                                        id="share-error-heading"
                                        className="text-lg font-semibold text-slate-100"
                                    >
                                        {pageErrorForbidden
                                            ? 'Share Access Denied'
                                            : 'Unable to Load Share'}
                                    </h2>
                                    <p className="text-sm text-slate-300">
                                        {pageErrorMessage ||
                                            'An error occurred while loading this shared link.'}
                                    </p>
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={() => void initializeShare()}
                                className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                            >
                                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                                Retry
                            </button>
                        </div>
                    </section>
                )}

                {/* Minimal Share Metadata Summary Card (shown in Locked & Ready phases) */}
                {metadata && (phase === 'locked' || phase === 'ready') && (
                    <section
                        aria-label="Shared item metadata"
                        className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 sm:p-6 shadow-xl"
                    >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                            <div className="flex items-start gap-3.5 min-w-0">
                                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-indigo-500/15 text-indigo-400 border border-indigo-500/25">
                                    {metadata.is_directory ? (
                                        <Folder className="h-5 w-5" aria-hidden="true" />
                                    ) : (
                                        <FileText className="h-5 w-5" aria-hidden="true" />
                                    )}
                                </div>
                                <div className="min-w-0">
                                    <h2 className="truncate text-lg font-semibold text-slate-100">
                                        {metadata.name}
                                    </h2>
                                    <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
                                        <span className="inline-flex items-center rounded-md bg-slate-800 px-2.5 py-0.5 font-medium text-slate-200 border border-slate-700/80">
                                            {metadata.is_directory
                                                ? 'Shared Folder'
                                                : 'Shared File'}
                                        </span>
                                        <span
                                            className={`inline-flex items-center rounded-md px-2.5 py-0.5 font-medium border ${
                                                metadata.allow_download
                                                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                                                    : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                                            }`}
                                        >
                                            {metadata.allow_download
                                                ? 'Downloadable'
                                                : 'View-only (downloads disabled)'}
                                        </span>
                                        {metadata.password_required && (
                                            <span className="inline-flex items-center gap-1 rounded-md bg-indigo-500/10 px-2.5 py-0.5 font-medium text-indigo-300 border border-indigo-500/30">
                                                {phase === 'ready' ? (
                                                    <>
                                                        <Unlock
                                                            className="h-3 w-3"
                                                            aria-hidden="true"
                                                        />
                                                        Unlocked
                                                    </>
                                                ) : (
                                                    <>
                                                        <Lock
                                                            className="h-3 w-3"
                                                            aria-hidden="true"
                                                        />
                                                        Password Protected
                                                    </>
                                                )}
                                            </span>
                                        )}
                                        <span className="inline-flex items-center gap-1 rounded-md bg-slate-800/80 px-2.5 py-0.5 text-slate-300 border border-slate-700/60">
                                            <Clock className="h-3 w-3 text-slate-400" aria-hidden="true" />
                                            {metadata.expires_at
                                                ? `Expires ${formatShareTimestamp(metadata.expires_at)}`
                                                : 'No expiration'}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>
                )}

                {/* 5. Password Unlock Form */}
                {metadata && phase === 'locked' && (
                    <section
                        aria-labelledby="share-unlock-heading"
                        className="rounded-2xl border border-slate-800 bg-slate-900/90 p-6 sm:p-8 shadow-xl"
                    >
                        <div className="max-w-md space-y-4">
                            <div className="space-y-1">
                                <h3
                                    id="share-unlock-heading"
                                    className="text-base font-semibold text-slate-100 flex items-center gap-2"
                                >
                                    <Lock className="h-4 w-4 text-indigo-400" aria-hidden="true" />
                                    Password Required
                                </h3>
                                <p className="text-sm text-slate-300">
                                    Enter the password for{' '}
                                    <span className="font-medium text-slate-100">
                                        {metadata.name}
                                    </span>{' '}
                                    to unlock access.
                                </p>
                            </div>

                            {unlockError && (
                                <div
                                    id="share-unlock-error"
                                    role="alert"
                                    className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200"
                                >
                                    {unlockError}
                                </div>
                            )}

                            <form
                                onSubmit={(e) => void handleUnlockSubmit(e)}
                                aria-label="Unlock password-protected share"
                                className="space-y-4"
                                noValidate
                            >
                                <div>
                                    <label
                                        htmlFor="share-password-input"
                                        className="block text-xs font-medium text-slate-300 mb-1.5"
                                    >
                                        Share Password
                                    </label>
                                    <div className="relative flex items-center">
                                        <input
                                            id="share-password-input"
                                            name="password"
                                            type={showPassword ? 'text' : 'password'}
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            disabled={isUnlocking}
                                            autoComplete="current-password"
                                            placeholder="Enter share password"
                                            aria-invalid={Boolean(unlockError)}
                                            aria-describedby={
                                                unlockError ? 'share-unlock-error' : undefined
                                            }
                                            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3.5 py-2.5 pr-10 text-sm text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/40 disabled:opacity-60"
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setShowPassword((prev) => !prev)}
                                            aria-label={
                                                showPassword ? 'Hide password' : 'Show password'
                                            }
                                            className="absolute right-2.5 rounded-lg p-1 text-slate-400 hover:text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                                        >
                                            {showPassword ? (
                                                <EyeOff className="h-4 w-4" aria-hidden="true" />
                                            ) : (
                                                <Eye className="h-4 w-4" aria-hidden="true" />
                                            )}
                                        </button>
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={isUnlocking}
                                    aria-busy={isUnlocking}
                                    className="inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-60"
                                >
                                    <Unlock className="h-4 w-4" aria-hidden="true" />
                                    {isUnlocking ? 'Unlocking...' : 'Unlock Share'}
                                </button>
                            </form>
                        </div>
                    </section>
                )}

                {/* 6. Unlocked Content View */}
                {metadata && phase === 'ready' && (
                    <section
                        aria-label={
                            metadata.is_directory
                                ? 'Shared folder browser'
                                : 'Shared file details'
                        }
                        className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 sm:p-6 shadow-xl space-y-5"
                    >
                        {actionError && (
                            <div
                                role="alert"
                                className="flex items-center justify-between gap-3 rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200"
                            >
                                <span>{actionError}</span>
                                <button
                                    type="button"
                                    onClick={() => setActionError(null)}
                                    className="rounded-lg border border-rose-500/30 px-2.5 py-1 text-xs font-medium text-rose-200 hover:bg-rose-500/20"
                                >
                                    Dismiss
                                </button>
                            </div>
                        )}

                        {!metadata.allow_download && (
                            <div
                                role="note"
                                className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs font-medium text-amber-200"
                            >
                                View-only share: browsing is enabled, but file downloads are disabled by the share owner.
                            </div>
                        )}

                        {/* Single-File Share View */}
                        {!metadata.is_directory && (
                            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                                <div className="space-y-1 min-w-0">
                                    <p className="text-sm font-semibold text-slate-100 truncate">
                                        {singleFileEntry?.name || metadata.name}
                                    </p>
                                    <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
                                        <span>
                                            Size:{' '}
                                            <strong className="font-medium text-slate-200">
                                                {singleFileEntry
                                                    ? formatShareBytes(singleFileEntry.size)
                                                    : '—'}
                                            </strong>
                                        </span>
                                        <span>
                                            Modified:{' '}
                                            <strong className="font-medium text-slate-200">
                                                {formatShareTimestamp(singleFileEntry?.modified)}
                                            </strong>
                                        </span>
                                    </div>
                                </div>

                                <div className="shrink-0">
                                    {metadata.allow_download ? (
                                        <button
                                            type="button"
                                            onClick={() =>
                                                void handleDownload(
                                                    '',
                                                    singleFileEntry?.name || metadata.name
                                                )
                                            }
                                            disabled={downloadingTarget !== null}
                                            aria-busy={downloadingTarget === '__single_file__'}
                                            aria-label={`Download ${
                                                singleFileEntry?.name || metadata.name
                                            }`}
                                            className="inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-60"
                                        >
                                            <Download className="h-4 w-4" aria-hidden="true" />
                                            {downloadingTarget === '__single_file__'
                                                ? 'Downloading...'
                                                : 'Download File'}
                                        </button>
                                    ) : (
                                        <button
                                            type="button"
                                            disabled
                                            aria-disabled="true"
                                            className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-800 bg-slate-900 px-4 py-2.5 text-xs font-medium text-slate-500 cursor-not-allowed"
                                        >
                                            Downloads Disabled
                                        </button>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Directory Share View */}
                        {metadata.is_directory && (
                            <div className="space-y-4">
                                {/* Breadcrumbs & Folder Controls */}
                                <div className="flex flex-wrap items-center justify-between gap-3">
                                    <nav
                                        aria-label="Shared folder breadcrumbs"
                                        className="flex flex-wrap items-center gap-1.5 text-xs"
                                    >
                                        {breadcrumbs.map((crumb, idx) => {
                                            const isCurrent = idx === breadcrumbs.length - 1;
                                            return (
                                                <React.Fragment key={crumb.path || '__root__'}>
                                                    {idx > 0 && (
                                                        <span
                                                            className="text-slate-600 select-none"
                                                            aria-hidden="true"
                                                        >
                                                            /
                                                        </span>
                                                    )}
                                                    <button
                                                        type="button"
                                                        onClick={() =>
                                                            handleNavigateDirectory(crumb.path)
                                                        }
                                                        disabled={isCurrent || isLoadingEntries}
                                                        aria-current={isCurrent ? 'page' : undefined}
                                                        className={`rounded-lg px-2.5 py-1 font-medium transition-colors ${
                                                            isCurrent
                                                                ? 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 cursor-default'
                                                                : 'bg-slate-800/80 text-slate-300 hover:bg-slate-800 hover:text-white'
                                                        }`}
                                                    >
                                                        {crumb.label}
                                                    </button>
                                                </React.Fragment>
                                            );
                                        })}
                                    </nav>

                                    <div className="flex items-center gap-2">
                                        {currentPath !== '' && (
                                            <button
                                                type="button"
                                                onClick={() =>
                                                    handleNavigateDirectory(
                                                        getParentSharePath(currentPath)
                                                    )
                                                }
                                                disabled={isLoadingEntries}
                                                aria-label="Up one folder level"
                                                className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-60"
                                            >
                                                <ArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
                                                Up
                                            </button>
                                        )}
                                        <button
                                            type="button"
                                            onClick={() =>
                                                token && void loadEntries(token, currentPath)
                                            }
                                            disabled={isLoadingEntries}
                                            aria-label="Refresh folder contents"
                                            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-60"
                                        >
                                            <RefreshCw
                                                className={`h-3.5 w-3.5 ${
                                                    isLoadingEntries ? 'animate-spin' : ''
                                                }`}
                                                aria-hidden="true"
                                            />
                                            Refresh
                                        </button>
                                    </div>
                                </div>

                                {/* Filter & Entry Count Bar */}
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                                    <div className="relative flex-1 max-w-sm">
                                        <label htmlFor="share-folder-filter" className="sr-only">
                                            Filter current folder
                                        </label>
                                        <Search
                                            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"
                                            aria-hidden="true"
                                        />
                                        <input
                                            id="share-folder-filter"
                                            type="search"
                                            value={filterQuery}
                                            onChange={(e) => setFilterQuery(e.target.value)}
                                            placeholder="Filter current folder..."
                                            className="w-full rounded-xl border border-slate-800 bg-slate-950 pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
                                        />
                                    </div>
                                    <p
                                        aria-live="polite"
                                        className="text-xs text-slate-400"
                                    >
                                        {directoryCount}{' '}
                                        {directoryCount === 1 ? 'folder' : 'folders'}, {fileCount}{' '}
                                        {fileCount === 1 ? 'file' : 'files'}
                                    </p>
                                </div>

                                {/* Entries Table */}
                                <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60">
                                    <table
                                        aria-label="Shared directory contents"
                                        className="w-full text-left border-collapse text-sm"
                                    >
                                        <thead>
                                            <tr className="border-b border-slate-800/90 text-xs uppercase tracking-wider text-slate-400 bg-slate-900/60">
                                                <th scope="col" className="py-3 px-4 font-semibold">
                                                    Name
                                                </th>
                                                <th scope="col" className="py-3 px-4 font-semibold">
                                                    Type
                                                </th>
                                                <th scope="col" className="py-3 px-4 font-semibold">
                                                    Size
                                                </th>
                                                <th scope="col" className="py-3 px-4 font-semibold">
                                                    Modified
                                                </th>
                                                <th
                                                    scope="col"
                                                    className="py-3 px-4 font-semibold text-right"
                                                >
                                                    Action
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-slate-800/60">
                                            {isLoadingEntries && entries.length === 0 ? (
                                                <tr>
                                                    <td
                                                        colSpan={5}
                                                        className="py-8 px-4 text-center text-xs text-slate-400"
                                                    >
                                                        Loading folder entries...
                                                    </td>
                                                </tr>
                                            ) : sortedFilteredEntries.length === 0 ? (
                                                <tr>
                                                    <td
                                                        colSpan={5}
                                                        className="py-8 px-4 text-center text-xs text-slate-400"
                                                    >
                                                        {filterQuery.trim()
                                                            ? 'No entries match your filter.'
                                                            : 'This shared folder is empty.'}
                                                    </td>
                                                </tr>
                                            ) : (
                                                sortedFilteredEntries.map((entry) => {
                                                    const isDir = entry.kind === 'directory';
                                                    const isDownloadingThis =
                                                        downloadingTarget === entry.path;

                                                    return (
                                                        <tr
                                                            key={entry.path}
                                                            className="hover:bg-slate-900/50 transition-colors"
                                                        >
                                                            <td className="py-3 px-4 font-medium text-slate-100">
                                                                {isDir ? (
                                                                    <button
                                                                        type="button"
                                                                        onClick={() =>
                                                                            handleNavigateDirectory(
                                                                                entry.path
                                                                            )
                                                                        }
                                                                        aria-label={`Open folder ${entry.name}`}
                                                                        className="inline-flex items-center gap-2.5 text-left text-indigo-300 hover:text-indigo-200 focus:outline-none focus:underline"
                                                                    >
                                                                        <Folder
                                                                            className="h-4 w-4 shrink-0 text-indigo-400"
                                                                            aria-hidden="true"
                                                                        />
                                                                        <span className="break-all">
                                                                            {entry.name}
                                                                        </span>
                                                                    </button>
                                                                ) : (
                                                                    <div className="inline-flex items-center gap-2.5 text-slate-200">
                                                                        <FileText
                                                                            className="h-4 w-4 shrink-0 text-slate-400"
                                                                            aria-hidden="true"
                                                                        />
                                                                        <span className="break-all">
                                                                            {entry.name}
                                                                        </span>
                                                                    </div>
                                                                )}
                                                            </td>
                                                            <td className="py-3 px-4 text-xs text-slate-400">
                                                                {isDir ? 'Folder' : 'File'}
                                                            </td>
                                                            <td className="py-3 px-4 text-xs text-slate-300 whitespace-nowrap">
                                                                {isDir
                                                                    ? '—'
                                                                    : formatShareBytes(entry.size)}
                                                            </td>
                                                            <td className="py-3 px-4 text-xs text-slate-400 whitespace-nowrap">
                                                                {formatShareTimestamp(
                                                                    entry.modified
                                                                )}
                                                            </td>
                                                            <td className="py-3 px-4 text-right whitespace-nowrap">
                                                                {isDir ? (
                                                                    <button
                                                                        type="button"
                                                                        onClick={() =>
                                                                            handleNavigateDirectory(
                                                                                entry.path
                                                                            )
                                                                        }
                                                                        aria-label={`Browse ${entry.name}`}
                                                                        className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700"
                                                                    >
                                                                        Open
                                                                    </button>
                                                                ) : metadata.allow_download ? (
                                                                    <button
                                                                        type="button"
                                                                        onClick={() =>
                                                                            void handleDownload(
                                                                                entry.path,
                                                                                entry.name
                                                                            )
                                                                        }
                                                                        disabled={
                                                                            downloadingTarget !== null
                                                                        }
                                                                        aria-busy={isDownloadingThis}
                                                                        aria-label={`Download ${entry.name}`}
                                                                        className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-60"
                                                                    >
                                                                        <Download
                                                                            className="h-3.5 w-3.5"
                                                                            aria-hidden="true"
                                                                        />
                                                                        {isDownloadingThis
                                                                            ? 'Downloading...'
                                                                            : 'Download'}
                                                                    </button>
                                                                ) : (
                                                                    <span className="inline-block rounded-md bg-slate-900 px-2 py-0.5 text-xs text-slate-500 border border-slate-800">
                                                                        View only
                                                                    </span>
                                                                )}
                                                            </td>
                                                        </tr>
                                                    );
                                                })
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}
                    </section>
                )}
            </div>
        </main>
    );
}

export default function PublicSharePage() {
    return (
        <Suspense
            fallback={
                <main
                    aria-label="Public shared content"
                    className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6"
                >
                    <div
                        role="status"
                        aria-live="polite"
                        className="flex flex-col items-center gap-3"
                    >
                        <div className="h-10 w-10 animate-spin rounded-full border-4 border-indigo-500/20 border-t-indigo-500" />
                        <p className="text-sm font-medium text-slate-300">
                            Loading public share...
                        </p>
                    </div>
                </main>
            }
        >
            <PublicShareView />
        </Suspense>
    );
}
