'use client';

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
    Shield,
    UserCheck,
    Plus,
    Trash2,
    ArrowUp,
    ArrowDown,
    Save,
    RotateCcw,
    AlertTriangle,
    CheckCircle2,
    Loader2,
    X,
    FolderLock,
    Regex,
} from 'lucide-react';
import { McBrowserRequestError, extractMcBrowserError } from '@/lib/mcbrowser';
import {
    MAX_ADMIN_POLICY_RULES,
    MCBROWSER_PERMISSION_KEYS,
    McBrowserAdminPolicyDocument,
    McBrowserAdminPolicyPermissions,
    McBrowserEditablePolicyRule,
    McBrowserPermissionKey,
    createDefaultAdminPolicyPermissions,
    fetchTargetUserMcBrowserPolicy,
    movePolicyRule,
    parseTargetUserId,
    saveTargetUserMcBrowserPolicy,
    serializeAdminPolicyPayload,
    toEditablePolicyRules,
    validateAdminScopeInput,
    validateEditablePolicyRule,
    validateTargetUserIdInput,
} from '@/lib/mcbrowser-policy-admin';

export interface McBrowserPolicyAdminProps {
    initialTargetUserId?: number | string;
    onPolicySaved?: (targetUserId: number, policy: McBrowserAdminPolicyDocument) => void;
    onClose?: () => void;
}

interface PermissionMetadata {
    key: McBrowserPermissionKey;
    label: string;
    description: string;
}

const PERMISSION_METADATA_LIST: ReadonlyArray<PermissionMetadata> = [
    {
        key: 'read',
        label: 'Read & Browse',
        description: 'List directories, inspect metadata, and preview permitted files.',
    },
    {
        key: 'create',
        label: 'Create & Upload',
        description: 'Upload files, create folders, and create new text documents.',
    },
    {
        key: 'rename',
        label: 'Rename & Move',
        description: 'Rename or move files and directories across allowed paths.',
    },
    {
        key: 'modify',
        label: 'Modify Content',
        description: 'Edit existing files and overwrite file contents.',
    },
    {
        key: 'delete',
        label: 'Delete Entries',
        description: 'Remove files and directories when no descendant path is denied.',
    },
    {
        key: 'share',
        label: 'Public Shares',
        description: 'Create and manage share links for permitted files and folders.',
    },
    {
        key: 'download',
        label: 'Download & Archive',
        description: 'Download individual files or multi-file archives.',
    },
    {
        key: 'execute',
        label: 'Safe Built-In Actions',
        description: 'Permit sandboxed file actions only; never host commands or shell execution.',
    },
];

function isAbortError(error: unknown): boolean {
    if (!error || typeof error !== 'object') {
        return false;
    }
    const candidate = error as { name?: unknown; code?: unknown };
    return candidate.name === 'AbortError' || candidate.code === 'ABORT_ERR';
}

export function McBrowserPolicyAdmin({
    initialTargetUserId,
    onPolicySaved,
    onClose,
}: McBrowserPolicyAdminProps) {
    const initialUserIdText =
        initialTargetUserId !== undefined && initialTargetUserId !== null
            ? String(initialTargetUserId).trim()
            : '';

    const [targetUserIdInput, setTargetUserIdInput] = useState<string>(initialUserIdText);
    const [loadedTargetUserId, setLoadedTargetUserId] = useState<number | null>(null);
    const [permissions, setPermissions] = useState<McBrowserAdminPolicyPermissions>(() =>
        createDefaultAdminPolicyPermissions()
    );
    const [scopeInput, setScopeInput] = useState<string>('');
    const [rules, setRules] = useState<McBrowserEditablePolicyRule[]>([]);
    const [lastLoadedSnapshot, setLastLoadedSnapshot] =
        useState<McBrowserAdminPolicyDocument | null>(null);

    const [isLoadingPolicy, setIsLoadingPolicy] = useState<boolean>(false);
    const [isSavingPolicy, setIsSavingPolicy] = useState<boolean>(false);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [statusMessage, setStatusMessage] = useState<string | null>(null);
    const [isSessionExpired, setIsSessionExpired] = useState<boolean>(false);

    const activeControllerRef = useRef<AbortController | null>(null);
    const requestSequenceRef = useRef<number>(0);
    const ruleCounterRef = useRef<number>(1);
    const isMountedRef = useRef<boolean>(true);

    const abortActiveRequest = useCallback(() => {
        if (activeControllerRef.current) {
            activeControllerRef.current.abort();
            activeControllerRef.current = null;
        }
    }, []);

    useEffect(() => {
        isMountedRef.current = true;
        const handleSessionExpired = () => {
            abortActiveRequest();
            if (!isMountedRef.current) {
                return;
            }
            setIsLoadingPolicy(false);
            setIsSavingPolicy(false);
            setIsSessionExpired(true);
            setStatusMessage(null);
            setErrorMessage(
                'Your administrator session has expired. Please sign in again before modifying user policies.'
            );
        };

        if (typeof window !== 'undefined') {
            window.addEventListener('af:session-expired', handleSessionExpired);
        }

        return () => {
            isMountedRef.current = false;
            abortActiveRequest();
            if (typeof window !== 'undefined') {
                window.removeEventListener('af:session-expired', handleSessionExpired);
            }
        };
    }, [abortActiveRequest]);

    const applyPolicyDocumentToState = useCallback(
        (targetUserId: number, document: McBrowserAdminPolicyDocument) => {
            const editableRules = toEditablePolicyRules(document.rules);
            ruleCounterRef.current = editableRules.length + 1;
            setLoadedTargetUserId(targetUserId);
            setTargetUserIdInput(String(targetUserId));
            setPermissions({ ...document.permissions });
            setScopeInput(document.scope);
            setRules(editableRules);
            setLastLoadedSnapshot(document);
        },
        []
    );

    const executeLoadPolicy = useCallback(
        async (rawTargetId: string | number) => {
            if (isSessionExpired || isSavingPolicy) {
                return;
            }

            let parsedUserId: number;
            try {
                parsedUserId = parseTargetUserId(rawTargetId);
            } catch (validationError) {
                setStatusMessage(null);
                setErrorMessage(
                    extractMcBrowserError(
                        validationError,
                        'Target user ID must be a positive integer.'
                    )
                );
                return;
            }

            abortActiveRequest();
            const controller = new AbortController();
            activeControllerRef.current = controller;
            requestSequenceRef.current += 1;
            const currentSequence = requestSequenceRef.current;

            setIsLoadingPolicy(true);
            setErrorMessage(null);
            setStatusMessage(null);

            try {
                const loadedDocument = await fetchTargetUserMcBrowserPolicy(
                    parsedUserId,
                    controller.signal
                );
                if (
                    !isMountedRef.current ||
                    controller.signal.aborted ||
                    currentSequence !== requestSequenceRef.current
                ) {
                    return;
                }
                applyPolicyDocumentToState(parsedUserId, loadedDocument);
                setStatusMessage(`Loaded McBrowser policy for user #${parsedUserId}.`);
            } catch (loadError) {
                if (
                    !isMountedRef.current ||
                    controller.signal.aborted ||
                    isAbortError(loadError) ||
                    currentSequence !== requestSequenceRef.current
                ) {
                    return;
                }
                if (loadError instanceof McBrowserRequestError && loadError.status === 401) {
                    setIsSessionExpired(true);
                    setErrorMessage(
                        'Your administrator session has expired. Please sign in again before loading user policies.'
                    );
                } else {
                    setErrorMessage(
                        extractMcBrowserError(
                            loadError,
                            `Failed to load policy for user #${parsedUserId}.`
                        )
                    );
                }
            } finally {
                if (isMountedRef.current && currentSequence === requestSequenceRef.current) {
                    setIsLoadingPolicy(false);
                    if (activeControllerRef.current === controller) {
                        activeControllerRef.current = null;
                    }
                }
            }
        },
        [abortActiveRequest, applyPolicyDocumentToState, isSavingPolicy, isSessionExpired]
    );

    useEffect(() => {
        if (initialUserIdText.length > 0 && validateTargetUserIdInput(initialUserIdText) === null) {
            void executeLoadPolicy(initialUserIdText);
        }
    }, [executeLoadPolicy, initialUserIdText]);

    const targetUserIdValidationError = useMemo(() => {
        if (targetUserIdInput.trim().length === 0) {
            return null;
        }
        return validateTargetUserIdInput(targetUserIdInput);
    }, [targetUserIdInput]);

    const scopeValidationError = useMemo(
        () => validateAdminScopeInput(scopeInput),
        [scopeInput]
    );

    const ruleValidationErrors = useMemo(
        () => rules.map((ruleItem) => validateEditablePolicyRule(ruleItem)),
        [rules]
    );

    const hasRuleValidationErrors = useMemo(
        () => ruleValidationErrors.some((message) => message !== null),
        [ruleValidationErrors]
    );

    const hasTargetIdMismatch = useMemo(() => {
        if (loadedTargetUserId === null) {
            return true;
        }
        return targetUserIdInput.trim() !== String(loadedTargetUserId);
    }, [loadedTargetUserId, targetUserIdInput]);

    const handleCancelInFlightRequest = useCallback(() => {
        requestSequenceRef.current += 1;
        abortActiveRequest();
        setIsLoadingPolicy(false);
        setIsSavingPolicy(false);
        setStatusMessage('Request cancelled.');
    }, [abortActiveRequest]);

    const handleLoadFormSubmit = useCallback(
        (event: React.FormEvent<HTMLFormElement>) => {
            event.preventDefault();
            void executeLoadPolicy(targetUserIdInput);
        },
        [executeLoadPolicy, targetUserIdInput]
    );

    const handleTogglePermission = useCallback((permissionKey: McBrowserPermissionKey) => {
        setPermissions((previousPermissions) => ({
            ...previousPermissions,
            [permissionKey]: !previousPermissions[permissionKey],
        }));
        setStatusMessage(null);
    }, []);

    const handleAllowAllPermissions = useCallback(() => {
        setPermissions(createDefaultAdminPolicyPermissions());
        setStatusMessage(null);
    }, []);

    const handleReadAndDownloadOnlyPermissions = useCallback(() => {
        setPermissions({
            read: true,
            create: false,
            rename: false,
            modify: false,
            delete: false,
            share: false,
            download: true,
            execute: false,
        });
        setStatusMessage(null);
    }, []);

    const handleAddRule = useCallback((useRegex: boolean) => {
        setRules((previousRules) => {
            if (previousRules.length >= MAX_ADMIN_POLICY_RULES) {
                return previousRules;
            }
            const nextRuleNumber = ruleCounterRef.current;
            ruleCounterRef.current += 1;
            const defaultPattern = useRegex ? '^/private/.*$' : 'private';
            return [
                ...previousRules,
                {
                    ruleId: `policy-rule-new-${nextRuleNumber}`,
                    path: defaultPattern,
                    allow: false,
                    regex: useRegex,
                    expression: useRegex ? defaultPattern : '',
                },
            ];
        });
        setStatusMessage(null);
    }, []);

    const handleUpdateRule = useCallback(
        (ruleIndex: number, patch: Partial<McBrowserEditablePolicyRule>) => {
            setRules((previousRules) =>
                previousRules.map((existingRule, currentIndex) => {
                    if (currentIndex !== ruleIndex) {
                        return existingRule;
                    }
                    const updatedRule: McBrowserEditablePolicyRule = {
                        ...existingRule,
                        ...patch,
                    };
                    if (patch.regex === true && updatedRule.expression.trim().length === 0) {
                        updatedRule.expression =
                            updatedRule.path.trim().length > 0
                                ? updatedRule.path
                                : '^/restricted/.*$';
                    }
                    if (patch.regex === false) {
                        updatedRule.expression = '';
                    }
                    return updatedRule;
                })
            );
            setStatusMessage(null);
        },
        []
    );

    const handleMoveRule = useCallback((fromIndex: number, toIndex: number) => {
        setRules((previousRules) => movePolicyRule(previousRules, fromIndex, toIndex));
        setStatusMessage(null);
    }, []);

    const handleRemoveRule = useCallback((ruleIndex: number) => {
        setRules((previousRules) =>
            previousRules.filter((_, currentIndex) => currentIndex !== ruleIndex)
        );
        setStatusMessage(null);
    }, []);

    const handleResetChanges = useCallback(() => {
        if (loadedTargetUserId === null || !lastLoadedSnapshot) {
            return;
        }
        applyPolicyDocumentToState(loadedTargetUserId, lastLoadedSnapshot);
        setErrorMessage(null);
        setStatusMessage(`Reverted unsaved changes for user #${loadedTargetUserId}.`);
    }, [applyPolicyDocumentToState, lastLoadedSnapshot, loadedTargetUserId]);

    const handleSavePolicy = useCallback(async () => {
        if (isSessionExpired || isLoadingPolicy || isSavingPolicy) {
            return;
        }

        if (loadedTargetUserId === null) {
            setErrorMessage('Load a target user policy before saving changes.');
            return;
        }

        if (hasTargetIdMismatch) {
            setErrorMessage(
                `Target user ID input (${targetUserIdInput.trim() || 'empty'}) does not match loaded user #${loadedTargetUserId}. Click Load Policy first.`
            );
            return;
        }

        let validatedPayload: McBrowserAdminPolicyDocument;
        try {
            validatedPayload = serializeAdminPolicyPayload({
                permissions,
                rules,
                scope: scopeInput,
            });
        } catch (validationError) {
            setStatusMessage(null);
            setErrorMessage(
                extractMcBrowserError(validationError, 'Policy contains invalid settings.')
            );
            return;
        }

        abortActiveRequest();
        const controller = new AbortController();
        activeControllerRef.current = controller;
        requestSequenceRef.current += 1;
        const currentSequence = requestSequenceRef.current;

        setIsSavingPolicy(true);
        setErrorMessage(null);
        setStatusMessage(null);

        try {
            const savedDocument = await saveTargetUserMcBrowserPolicy(
                loadedTargetUserId,
                validatedPayload,
                controller.signal
            );
            if (
                !isMountedRef.current ||
                controller.signal.aborted ||
                currentSequence !== requestSequenceRef.current
            ) {
                return;
            }
            applyPolicyDocumentToState(loadedTargetUserId, savedDocument);
            setStatusMessage(`Saved McBrowser policy for user #${loadedTargetUserId}.`);
            if (onPolicySaved) {
                onPolicySaved(loadedTargetUserId, savedDocument);
            }
        } catch (saveError) {
            if (
                !isMountedRef.current ||
                controller.signal.aborted ||
                isAbortError(saveError) ||
                currentSequence !== requestSequenceRef.current
            ) {
                return;
            }
            if (saveError instanceof McBrowserRequestError && saveError.status === 401) {
                setIsSessionExpired(true);
                setErrorMessage(
                    'Your administrator session has expired. Unsaved policy changes were not persisted.'
                );
            } else {
                setErrorMessage(
                    extractMcBrowserError(
                        saveError,
                        `Failed to save policy for user #${loadedTargetUserId}.`
                    )
                );
            }
        } finally {
            if (isMountedRef.current && currentSequence === requestSequenceRef.current) {
                setIsSavingPolicy(false);
                if (activeControllerRef.current === controller) {
                    activeControllerRef.current = null;
                }
            }
        }
    }, [
        abortActiveRequest,
        applyPolicyDocumentToState,
        hasTargetIdMismatch,
        isLoadingPolicy,
        isSavingPolicy,
        isSessionExpired,
        loadedTargetUserId,
        onPolicySaved,
        permissions,
        rules,
        scopeInput,
        targetUserIdInput,
    ]);

    const isBusy = isLoadingPolicy || isSavingPolicy;
    const isEditorDisabled = isBusy || isSessionExpired || loadedTargetUserId === null;
    const canSavePolicy =
        !isEditorDisabled &&
        !hasTargetIdMismatch &&
        scopeValidationError === null &&
        !hasRuleValidationErrors &&
        rules.length <= MAX_ADMIN_POLICY_RULES;

    return (
        <section
            aria-label="McBrowser User Policy Administration"
            aria-busy={isBusy}
            data-testid="mcbrowser-policy-admin"
            className="rounded-xl border border-slate-800 bg-slate-950/90 p-5 text-slate-100 shadow-xl"
        >
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div className="flex items-center gap-2.5">
                    <Shield className="h-5 w-5 text-emerald-400" aria-hidden="true" />
                    <div>
                        <h2 className="text-base font-semibold text-white">
                            McBrowser User File Policy Editor
                        </h2>
                        <p className="text-xs text-slate-400">
                            Configure per-user workspace scope, 7 file operation flags, and ordered
                            prefix/regex access rules.
                        </p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <span
                        data-testid="policy-admin-never-execute-badge"
                        className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-300"
                    >
                        Host shell execution permanently disabled
                    </span>
                    {onClose && (
                        <button
                            type="button"
                            onClick={onClose}
                            data-testid="policy-admin-close-button"
                            aria-label="Close policy editor"
                            className="rounded-lg border border-slate-700 bg-slate-900 p-1.5 text-slate-300 hover:bg-slate-800 hover:text-white"
                        >
                            <X className="h-4 w-4" aria-hidden="true" />
                        </button>
                    )}
                </div>
            </div>

            {isSessionExpired && (
                <div
                    role="alert"
                    data-testid="policy-admin-session-expired-banner"
                    className="mt-4 flex items-start gap-2.5 rounded-lg border border-red-500/40 bg-red-950/60 p-3 text-xs text-red-200"
                >
                    <AlertTriangle
                        className="mt-0.5 h-4 w-4 shrink-0 text-red-400"
                        aria-hidden="true"
                    />
                    <div>
                        <p className="font-semibold text-red-100">Administrator Session Expired</p>
                        <p className="mt-0.5">
                            {errorMessage ||
                                'Your session is no longer valid. Please re-authenticate to continue managing user policies.'}
                        </p>
                    </div>
                </div>
            )}

            {errorMessage && !isSessionExpired && (
                <div
                    role="alert"
                    data-testid="policy-admin-error-banner"
                    className="mt-4 flex items-start gap-2.5 rounded-lg border border-red-500/40 bg-red-950/50 p-3 text-xs text-red-200"
                >
                    <AlertTriangle
                        className="mt-0.5 h-4 w-4 shrink-0 text-red-400"
                        aria-hidden="true"
                    />
                    <span>{errorMessage}</span>
                </div>
            )}

            {statusMessage && !errorMessage && (
                <div
                    role="status"
                    aria-live="polite"
                    data-testid="policy-admin-save-success"
                    className="mt-4 flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-950/40 p-3 text-xs text-emerald-200"
                >
                    <CheckCircle2
                        className="h-4 w-4 shrink-0 text-emerald-400"
                        aria-hidden="true"
                    />
                    <span>{statusMessage}</span>
                </div>
            )}

            <form
                onSubmit={handleLoadFormSubmit}
                className="mt-4 flex flex-wrap items-end gap-3 rounded-lg border border-slate-800/80 bg-slate-900/60 p-3.5"
            >
                <div className="min-w-[200px] flex-1">
                    <label
                        htmlFor="mcbrowser-policy-target-user-id"
                        className="block text-xs font-medium text-slate-300"
                    >
                        Target User ID (numeric)
                    </label>
                    <input
                        id="mcbrowser-policy-target-user-id"
                        data-testid="policy-admin-target-user-input"
                        type="text"
                        inputMode="numeric"
                        value={targetUserIdInput}
                        disabled={isSavingPolicy || isSessionExpired}
                        onChange={(event) => {
                            setTargetUserIdInput(event.target.value);
                            setStatusMessage(null);
                        }}
                        placeholder="e.g. 2"
                        aria-invalid={targetUserIdValidationError !== null}
                        className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                    />
                    {targetUserIdValidationError && (
                        <p
                            data-testid="policy-admin-target-user-error"
                            className="mt-1 text-xs text-amber-300"
                        >
                            {targetUserIdValidationError}
                        </p>
                    )}
                </div>

                <div className="flex items-center gap-2">
                    <button
                        type="submit"
                        data-testid="policy-admin-load-button"
                        disabled={
                            isSavingPolicy ||
                            isSessionExpired ||
                            targetUserIdInput.trim().length === 0 ||
                            targetUserIdValidationError !== null
                        }
                        className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                        {isLoadingPolicy ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                        ) : (
                            <UserCheck className="h-3.5 w-3.5" aria-hidden="true" />
                        )}
                        <span>{isLoadingPolicy ? 'Loading...' : 'Load Policy'}</span>
                    </button>

                    {isBusy && (
                        <button
                            type="button"
                            onClick={handleCancelInFlightRequest}
                            data-testid="policy-admin-cancel-request"
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700"
                        >
                            Cancel
                        </button>
                    )}
                </div>

                <div className="ml-auto flex items-center gap-2">
                    {loadedTargetUserId !== null ? (
                        <span
                            data-testid="policy-admin-loaded-user-badge"
                            className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-300"
                        >
                            Editing User #{loadedTargetUserId}
                        </span>
                    ) : (
                        <span
                            data-testid="policy-admin-unloaded-badge"
                            className="rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-400"
                        >
                            No target user loaded
                        </span>
                    )}
                </div>
            </form>

            {loadedTargetUserId !== null && hasTargetIdMismatch && (
                <div
                    role="status"
                    data-testid="policy-admin-target-mismatch-warning"
                    className="mt-3 rounded-lg border border-amber-500/40 bg-amber-950/40 px-3 py-2 text-xs text-amber-200"
                >
                    Target User ID input has changed from loaded User #{loadedTargetUserId}. Click{' '}
                    <strong>Load Policy</strong> to load the new user before saving.
                </div>
            )}

            <div className="mt-5 grid gap-5 lg:grid-cols-2">
                <fieldset
                    disabled={isEditorDisabled}
                    className="rounded-lg border border-slate-800 bg-slate-900/40 p-4 disabled:opacity-60"
                >
                    <legend className="px-1 text-xs font-semibold uppercase tracking-wider text-slate-300">
                        Operation Permissions (8 Flags)
                    </legend>
                    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs text-slate-400">
                            Safe actions require explicit opt-in; host shell execution is never allowed.
                        </span>
                        <div className="flex items-center gap-1.5">
                            <button
                                type="button"
                                onClick={handleAllowAllPermissions}
                                data-testid="policy-perm-allow-all"
                                className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-700"
                            >
                                Standard File Operations
                            </button>
                            <button
                                type="button"
                                onClick={handleReadAndDownloadOnlyPermissions}
                                data-testid="policy-perm-read-only"
                                className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-700"
                            >
                                Read &amp; Download Only
                            </button>
                        </div>
                    </div>

                    <div className="space-y-2">
                        {PERMISSION_METADATA_LIST.map((item) => {
                            const checkboxId = `mcbrowser-policy-perm-${item.key}`;
                            const isChecked = Boolean(permissions[item.key]);
                            return (
                                <label
                                    key={item.key}
                                    htmlFor={checkboxId}
                                    className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-slate-800/80 bg-slate-950/60 p-2.5 hover:border-slate-700"
                                >
                                    <input
                                        id={checkboxId}
                                        data-testid={`policy-perm-${item.key}`}
                                        type="checkbox"
                                        checked={isChecked}
                                        onChange={() => handleTogglePermission(item.key)}
                                        className="mt-0.5 h-4 w-4 rounded border-slate-600 bg-slate-900 text-emerald-500 focus:ring-emerald-500"
                                    />
                                    <span className="flex-1">
                                        <span className="block text-xs font-medium text-slate-100">
                                            {item.label}{' '}
                                            <code className="text-[11px] text-slate-400">
                                                ({item.key})
                                            </code>
                                        </span>
                                        <span className="block text-[11px] text-slate-400">
                                            {item.description}
                                        </span>
                                    </span>
                                </label>
                            );
                        })}
                    </div>
                </fieldset>

                <div className="flex flex-col gap-5">
                    <fieldset
                        disabled={isEditorDisabled}
                        className="rounded-lg border border-slate-800 bg-slate-900/40 p-4 disabled:opacity-60"
                    >
                        <legend className="px-1 text-xs font-semibold uppercase tracking-wider text-slate-300">
                            Relative Scope Subdirectory
                        </legend>
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                            <FolderLock
                                className="h-4 w-4 shrink-0 text-emerald-400"
                                aria-hidden="true"
                            />
                            <span>
                                Restrict the user root within their isolated prison directory. Leave
                                empty for their root workspace.
                            </span>
                        </div>
                        <div className="mt-3">
                            <label
                                htmlFor="mcbrowser-policy-scope-input"
                                className="block text-xs font-medium text-slate-300"
                            >
                                Relative Scope Path
                            </label>
                            <input
                                id="mcbrowser-policy-scope-input"
                                data-testid="policy-admin-scope-input"
                                type="text"
                                value={scopeInput}
                                onChange={(event) => {
                                    setScopeInput(event.target.value);
                                    setStatusMessage(null);
                                }}
                                placeholder="e.g. projects/alpha (or empty for root)"
                                aria-invalid={scopeValidationError !== null}
                                className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                            />
                            {scopeValidationError && (
                                <p
                                    role="alert"
                                    data-testid="policy-admin-scope-error"
                                    className="mt-1.5 text-xs text-red-300"
                                >
                                    {scopeValidationError}
                                </p>
                            )}
                        </div>
                    </fieldset>

                    <fieldset
                        disabled={isEditorDisabled}
                        className="flex-1 rounded-lg border border-slate-800 bg-slate-900/40 p-4 disabled:opacity-60"
                    >
                        <legend className="px-1 text-xs font-semibold uppercase tracking-wider text-slate-300">
                            Ordered Path &amp; Regex Rules ({rules.length}/{MAX_ADMIN_POLICY_RULES})
                        </legend>
                        <p className="text-xs text-slate-400">
                            Evaluated top-to-bottom; the <strong>last matching rule wins</strong>.
                            Prefix rules match segment boundaries; regex rules match against{' '}
                            <code>/&lt;normalized_path&gt;</code>.
                        </p>

                        <div className="mt-3 flex flex-wrap items-center gap-2">
                            <button
                                type="button"
                                onClick={() => handleAddRule(false)}
                                data-testid="policy-admin-add-rule"
                                disabled={rules.length >= MAX_ADMIN_POLICY_RULES}
                                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-100 hover:bg-slate-700 disabled:opacity-50"
                            >
                                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                                <span>Add Prefix Rule</span>
                            </button>
                            <button
                                type="button"
                                onClick={() => handleAddRule(true)}
                                data-testid="policy-admin-add-regex-rule"
                                disabled={rules.length >= MAX_ADMIN_POLICY_RULES}
                                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-100 hover:bg-slate-700 disabled:opacity-50"
                            >
                                <Regex className="h-3.5 w-3.5" aria-hidden="true" />
                                <span>Add Regex Rule</span>
                            </button>
                        </div>

                        {rules.length === 0 ? (
                            <p
                                data-testid="policy-admin-empty-rules"
                                className="mt-4 rounded-lg border border-dashed border-slate-800 p-4 text-center text-xs text-slate-400"
                            >
                                No path or regex rules configured. All paths within the user scope
                                are permitted by default.
                            </p>
                        ) : (
                            <div className="mt-3 space-y-2.5">
                                {rules.map((ruleItem, ruleIndex) => {
                                    const validationError = ruleValidationErrors[ruleIndex];
                                    return (
                                        <div
                                            key={ruleItem.ruleId}
                                            data-testid={`policy-rule-row-${ruleIndex}`}
                                            className="rounded-lg border border-slate-800 bg-slate-950/80 p-3"
                                        >
                                            <div className="flex flex-wrap items-center gap-2">
                                                <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[11px] font-mono text-slate-300">
                                                    #{ruleIndex + 1}
                                                </span>

                                                <label
                                                    htmlFor={`policy-rule-allow-${ruleIndex}`}
                                                    className="sr-only"
                                                >
                                                    Rule {ruleIndex + 1} Effect
                                                </label>
                                                <select
                                                    id={`policy-rule-allow-${ruleIndex}`}
                                                    data-testid={`policy-rule-allow-${ruleIndex}`}
                                                    value={ruleItem.allow ? 'allow' : 'deny'}
                                                    onChange={(event) =>
                                                        handleUpdateRule(ruleIndex, {
                                                            allow: event.target.value === 'allow',
                                                        })
                                                    }
                                                    className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-white"
                                                >
                                                    <option value="deny">Deny</option>
                                                    <option value="allow">Allow</option>
                                                </select>

                                                <label
                                                    htmlFor={`policy-rule-regex-${ruleIndex}`}
                                                    className="inline-flex items-center gap-1.5 text-xs text-slate-300"
                                                >
                                                    <input
                                                        id={`policy-rule-regex-${ruleIndex}`}
                                                        data-testid={`policy-rule-regex-${ruleIndex}`}
                                                        type="checkbox"
                                                        checked={ruleItem.regex}
                                                        onChange={(event) =>
                                                            handleUpdateRule(ruleIndex, {
                                                                regex: event.target.checked,
                                                            })
                                                        }
                                                        className="h-3.5 w-3.5 rounded border-slate-600 bg-slate-900 text-emerald-500"
                                                    />
                                                    <span>Regex</span>
                                                </label>

                                                <div className="ml-auto flex items-center gap-1">
                                                    <button
                                                        type="button"
                                                        onClick={() =>
                                                            handleMoveRule(
                                                                ruleIndex,
                                                                ruleIndex - 1
                                                            )
                                                        }
                                                        disabled={ruleIndex === 0}
                                                        data-testid={`policy-rule-move-up-${ruleIndex}`}
                                                        aria-label={`Move rule ${ruleIndex + 1} up`}
                                                        className="rounded border border-slate-700 bg-slate-900 p-1 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
                                                    >
                                                        <ArrowUp
                                                            className="h-3.5 w-3.5"
                                                            aria-hidden="true"
                                                        />
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() =>
                                                            handleMoveRule(
                                                                ruleIndex,
                                                                ruleIndex + 1
                                                            )
                                                        }
                                                        disabled={ruleIndex === rules.length - 1}
                                                        data-testid={`policy-rule-move-down-${ruleIndex}`}
                                                        aria-label={`Move rule ${ruleIndex + 1} down`}
                                                        className="rounded border border-slate-700 bg-slate-900 p-1 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
                                                    >
                                                        <ArrowDown
                                                            className="h-3.5 w-3.5"
                                                            aria-hidden="true"
                                                        />
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleRemoveRule(ruleIndex)}
                                                        data-testid={`policy-rule-remove-${ruleIndex}`}
                                                        aria-label={`Remove rule ${ruleIndex + 1}`}
                                                        className="rounded border border-red-900/60 bg-red-950/40 p-1 text-red-300 hover:bg-red-900/50"
                                                    >
                                                        <Trash2
                                                            className="h-3.5 w-3.5"
                                                            aria-hidden="true"
                                                        />
                                                    </button>
                                                </div>
                                            </div>

                                            <div className="mt-2 grid gap-2 sm:grid-cols-2">
                                                <div
                                                    className={
                                                        ruleItem.regex ? '' : 'sm:col-span-2'
                                                    }
                                                >
                                                    <label
                                                        htmlFor={`policy-rule-path-${ruleIndex}`}
                                                        className="block text-[11px] text-slate-400"
                                                    >
                                                        {ruleItem.regex
                                                            ? 'Rule Label / Path Identifier'
                                                            : 'Relative Prefix Path'}
                                                    </label>
                                                    <input
                                                        id={`policy-rule-path-${ruleIndex}`}
                                                        data-testid={`policy-rule-path-${ruleIndex}`}
                                                        type="text"
                                                        value={ruleItem.path}
                                                        onChange={(event) =>
                                                            handleUpdateRule(ruleIndex, {
                                                                path: event.target.value,
                                                            })
                                                        }
                                                        placeholder={
                                                            ruleItem.regex
                                                                ? 'e.g. public-logs'
                                                                : 'e.g. private/vault'
                                                        }
                                                        className="mt-0.5 w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-white"
                                                    />
                                                </div>

                                                {ruleItem.regex && (
                                                    <div>
                                                        <label
                                                            htmlFor={`policy-rule-expression-${ruleIndex}`}
                                                            className="block text-[11px] text-slate-400"
                                                        >
                                                            Regex Expression (1..2048 bytes)
                                                        </label>
                                                        <input
                                                            id={`policy-rule-expression-${ruleIndex}`}
                                                            data-testid={`policy-rule-expression-${ruleIndex}`}
                                                            type="text"
                                                            value={ruleItem.expression}
                                                            onChange={(event) =>
                                                                handleUpdateRule(ruleIndex, {
                                                                    expression: event.target.value,
                                                                })
                                                            }
                                                            placeholder="e.g. ^/logs/public-.*\.log$"
                                                            className="mt-0.5 w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-white"
                                                        />
                                                    </div>
                                                )}
                                            </div>

                                            {validationError && (
                                                <p
                                                    role="alert"
                                                    data-testid={`policy-rule-error-${ruleIndex}`}
                                                    className="mt-1.5 text-xs text-red-300"
                                                >
                                                    {validationError}
                                                </p>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </fieldset>
                </div>
            </div>

            <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4">
                <button
                    type="button"
                    onClick={handleResetChanges}
                    data-testid="policy-admin-reset-button"
                    disabled={isEditorDisabled || lastLoadedSnapshot === null}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
                >
                    <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Reset to Loaded Policy</span>
                </button>

                <button
                    type="button"
                    onClick={() => void handleSavePolicy()}
                    data-testid="policy-admin-save-button"
                    disabled={!canSavePolicy}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
                >
                    {isSavingPolicy ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                    ) : (
                        <Save className="h-3.5 w-3.5" aria-hidden="true" />
                    )}
                    <span>
                        {isSavingPolicy
                            ? 'Saving Policy...'
                            : loadedTargetUserId !== null
                              ? `Save Policy for User #${loadedTargetUserId}`
                              : 'Save Policy'}
                    </span>
                </button>
            </div>
        </section>
    );
}

export default McBrowserPolicyAdmin;
