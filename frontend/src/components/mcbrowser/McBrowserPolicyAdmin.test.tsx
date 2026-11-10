import { TextEncoder, TextDecoder } from 'util';
import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import McBrowserPolicyAdmin from '@/components/mcbrowser/McBrowserPolicyAdmin';
import { McBrowserRequestError } from '@/lib/mcbrowser';
import {
    McBrowserAdminPolicyDocument,
    createDefaultAdminPolicyPermissions,
    fetchTargetUserMcBrowserPolicy,
    saveTargetUserMcBrowserPolicy,
} from '@/lib/mcbrowser-policy-admin';

Object.assign(globalThis, { TextEncoder, TextDecoder });

jest.mock('@/lib/mcbrowser-policy-admin', () => {
    const actualModule = jest.requireActual('@/lib/mcbrowser-policy-admin');
    return {
        ...actualModule,
        fetchTargetUserMcBrowserPolicy: jest.fn(),
        saveTargetUserMcBrowserPolicy: jest.fn(),
    };
});

const mockedFetchPolicy = fetchTargetUserMcBrowserPolicy as jest.MockedFunction<
    typeof fetchTargetUserMcBrowserPolicy
>;
const mockedSavePolicy = saveTargetUserMcBrowserPolicy as jest.MockedFunction<
    typeof saveTargetUserMcBrowserPolicy
>;

describe('McBrowserPolicyAdmin component', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('loads target policy with default-off safe actions, edits ordered rules, and saves via PUT', async () => {
        const initialDocument: McBrowserAdminPolicyDocument = {
            permissions: {
                read: true,
                create: true,
                rename: true,
                modify: true,
                delete: false,
                share: true,
                download: true,
                execute: false,
            },
            rules: [
                {
                    path: 'private/vault',
                    allow: false,
                    regex: false,
                },
                {
                    path: 'public-logs',
                    allow: true,
                    regex: true,
                    regexp: { raw: '^/private/vault/public-.*\\.log$' },
                },
            ],
            scope: 'tenants/alice',
        };

        mockedFetchPolicy.mockResolvedValueOnce(initialDocument);

        const onPolicySaved = jest.fn();
        render(<McBrowserPolicyAdmin onPolicySaved={onPolicySaved} />);
        expect(screen.getByText(/Configure per-user workspace scope/)).toHaveTextContent('8 file operation flags');
        expect(screen.getByText('Operation Permissions (8 Flags)')).toBeInTheDocument();
        expect(screen.queryByText(/7 file operation flags/)).not.toBeInTheDocument();

        expect(screen.getByTestId('policy-admin-never-execute-badge')).toBeInTheDocument();
        expect(screen.getByTestId('policy-admin-never-execute-badge')).toHaveTextContent('Host shell execution permanently disabled');

        const userInput = screen.getByTestId('policy-admin-target-user-input');
        fireEvent.change(userInput, { target: { value: '2' } });
        fireEvent.click(screen.getByTestId('policy-admin-load-button'));

        await waitFor(() => {
            expect(screen.getByTestId('policy-admin-loaded-user-badge')).toHaveTextContent(
                'Editing User #2'
            );
        });

        expect(mockedFetchPolicy).toHaveBeenCalledWith(2, expect.any(AbortSignal));

        for (const permKey of [
            'read',
            'create',
            'rename',
            'modify',
            'delete',
            'share',
            'download',
            'execute',
        ]) {
            expect(screen.getByTestId(`policy-perm-${permKey}`)).toBeInTheDocument();
        }
        expect((screen.getByTestId('policy-perm-delete') as HTMLInputElement).checked).toBe(false);
        expect((screen.getByTestId('policy-perm-execute') as HTMLInputElement).checked).toBe(false);
        expect((screen.getByTestId('policy-admin-scope-input') as HTMLInputElement).value).toBe(
            'tenants/alice'
        );

        fireEvent.click(screen.getByTestId('policy-perm-create'));
        expect((screen.getByTestId('policy-perm-create') as HTMLInputElement).checked).toBe(false);

        fireEvent.change(screen.getByTestId('policy-admin-scope-input'), {
            target: { value: 'tenants/alice/workspace' },
        });

        fireEvent.click(screen.getByTestId('policy-rule-move-down-0'));
        expect((screen.getByTestId('policy-rule-path-0') as HTMLInputElement).value).toBe(
            'public-logs'
        );
        expect((screen.getByTestId('policy-rule-path-1') as HTMLInputElement).value).toBe(
            'private/vault'
        );

        fireEvent.click(screen.getByTestId('policy-admin-add-regex-rule'));
        fireEvent.change(screen.getByTestId('policy-rule-path-2'), {
            target: { value: 'audit-allow' },
        });
        fireEvent.change(screen.getByTestId('policy-rule-allow-2'), {
            target: { value: 'allow' },
        });
        fireEvent.change(screen.getByTestId('policy-rule-expression-2'), {
            target: { value: '^/audit/.*\\.txt$' },
        });

        const expectedSavedDocument: McBrowserAdminPolicyDocument = {
            permissions: {
                read: true,
                create: false,
                rename: true,
                modify: true,
                delete: false,
                share: true,
                download: true,
                execute: false,
            },
            rules: [
                {
                    path: 'public-logs',
                    allow: true,
                    regex: true,
                    regexp: { raw: '^/private/vault/public-.*\\.log$' },
                },
                {
                    path: 'private/vault',
                    allow: false,
                    regex: false,
                },
                {
                    path: 'audit-allow',
                    allow: true,
                    regex: true,
                    regexp: { raw: '^/audit/.*\\.txt$' },
                },
            ],
            scope: 'tenants/alice/workspace',
        };
        mockedSavePolicy.mockResolvedValueOnce(expectedSavedDocument);

        fireEvent.click(screen.getByTestId('policy-admin-save-button'));

        await waitFor(() => {
            expect(screen.getByTestId('policy-admin-save-success')).toHaveTextContent(
                'Saved McBrowser policy for user #2.'
            );
        });

        expect(mockedSavePolicy).toHaveBeenCalledWith(
            2,
            expectedSavedDocument,
            expect.any(AbortSignal)
        );
        expect(onPolicySaved).toHaveBeenCalledWith(2, expectedSavedDocument);
    });

    it('blocks saving when target user ID input changes without loading, and supports resetting to loaded policy', async () => {
        const loadedDoc: McBrowserAdminPolicyDocument = {
            permissions: createDefaultAdminPolicyPermissions(),
            rules: [{ path: 'docs/confidential', allow: false, regex: false }],
            scope: 'team/docs',
        };
        mockedFetchPolicy.mockResolvedValueOnce(loadedDoc);

        render(<McBrowserPolicyAdmin initialTargetUserId={5} />);

        await waitFor(() => {
            expect(screen.getByTestId('policy-admin-loaded-user-badge')).toHaveTextContent(
                'Editing User #5'
            );
        });

        fireEvent.click(screen.getByTestId('policy-perm-read-only'));
        expect((screen.getByTestId('policy-perm-modify') as HTMLInputElement).checked).toBe(false);
        fireEvent.click(screen.getByTestId('policy-perm-execute'));
        expect((screen.getByTestId('policy-perm-execute') as HTMLInputElement).checked).toBe(true);
        fireEvent.click(screen.getByTestId('policy-perm-allow-all'));
        expect((screen.getByTestId('policy-perm-execute') as HTMLInputElement).checked).toBe(false);
        fireEvent.click(screen.getByTestId('policy-perm-execute'));
        fireEvent.click(screen.getByTestId('policy-perm-read-only'));
        expect((screen.getByTestId('policy-perm-execute') as HTMLInputElement).checked).toBe(false);

        fireEvent.change(screen.getByTestId('policy-admin-target-user-input'), {
            target: { value: '9' },
        });
        expect(screen.getByTestId('policy-admin-target-mismatch-warning')).toBeInTheDocument();
        expect(screen.getByTestId('policy-admin-save-button')).toBeDisabled();

        fireEvent.click(screen.getByTestId('policy-admin-reset-button'));
        expect(
            (screen.getByTestId('policy-admin-target-user-input') as HTMLInputElement).value
        ).toBe('5');
        expect((screen.getByTestId('policy-perm-modify') as HTMLInputElement).checked).toBe(true);
        expect(screen.getByTestId('policy-admin-save-button')).not.toBeDisabled();
    });

    it('validates scope and rule inputs inline and disables save while invalid', async () => {
        mockedFetchPolicy.mockResolvedValueOnce({
            permissions: createDefaultAdminPolicyPermissions(),
            rules: [],
            scope: '',
        });

        render(<McBrowserPolicyAdmin initialTargetUserId={3} />);

        await waitFor(() => {
            expect(screen.getByTestId('policy-admin-loaded-user-badge')).toHaveTextContent(
                'Editing User #3'
            );
        });

        fireEvent.change(screen.getByTestId('policy-admin-scope-input'), {
            target: { value: '/etc/passwd' },
        });
        expect(screen.getByTestId('policy-admin-scope-error')).toBeInTheDocument();
        expect(screen.getByTestId('policy-admin-save-button')).toBeDisabled();

        fireEvent.change(screen.getByTestId('policy-admin-scope-input'), {
            target: { value: 'valid/scope' },
        });
        expect(screen.queryByTestId('policy-admin-scope-error')).not.toBeInTheDocument();

        fireEvent.click(screen.getByTestId('policy-admin-add-regex-rule'));
        fireEvent.change(screen.getByTestId('policy-rule-expression-0'), {
            target: { value: '[unclosed' },
        });
        expect(screen.getByTestId('policy-rule-error-0')).toBeInTheDocument();
        expect(screen.getByTestId('policy-admin-save-button')).toBeDisabled();
    });

    it('handles request cancellation, stale response superseding, and session expiration safeguards', async () => {
        let resolveFirstLoad: ((doc: McBrowserAdminPolicyDocument) => void) | null = null;
        mockedFetchPolicy.mockImplementationOnce(
            () =>
                new Promise<McBrowserAdminPolicyDocument>((resolve) => {
                    resolveFirstLoad = resolve;
                })
        );

        render(<McBrowserPolicyAdmin />);

        fireEvent.change(screen.getByTestId('policy-admin-target-user-input'), {
            target: { value: '4' },
        });
        fireEvent.click(screen.getByTestId('policy-admin-load-button'));

        expect(screen.getByTestId('policy-admin-cancel-request')).toBeInTheDocument();
        fireEvent.click(screen.getByTestId('policy-admin-cancel-request'));

        if (resolveFirstLoad) {
            await act(async () => {
                resolveFirstLoad?.({
                    permissions: createDefaultAdminPolicyPermissions(),
                    rules: [],
                    scope: 'stale/scope',
                });
            });
        }

        expect(screen.queryByTestId('policy-admin-loaded-user-badge')).not.toBeInTheDocument();

        mockedFetchPolicy.mockRejectedValueOnce(
            new McBrowserRequestError(404, 'NOT_FOUND', 'Target user account not found')
        );
        fireEvent.click(screen.getByTestId('policy-admin-load-button'));

        await waitFor(() => {
            expect(screen.getByTestId('policy-admin-error-banner')).toHaveTextContent(
                'Target user account not found (NOT_FOUND)'
            );
        });

        act(() => {
            window.dispatchEvent(new CustomEvent('af:session-expired'));
        });

        expect(screen.getByTestId('policy-admin-session-expired-banner')).toBeInTheDocument();
        expect(screen.getByTestId('policy-admin-load-button')).toBeDisabled();
        expect(screen.getByTestId('policy-admin-save-button')).toBeDisabled();
    });
});
