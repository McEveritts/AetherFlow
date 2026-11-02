import { TextEncoder, TextDecoder } from 'util';
import { apiFetch } from '@/lib/fetcher';
import { MCBROWSER_BASE, McBrowserRequestError } from '@/lib/mcbrowser';
import {
    MAX_ADMIN_POLICY_RULES,
    MCBROWSER_PERMISSION_KEYS,
    createDefaultAdminPolicyDocument,
    createDefaultAdminPolicyPermissions,
    fetchTargetUserMcBrowserPolicy,
    movePolicyRule,
    normalizeAdminPathRule,
    normalizeAdminPolicyPermissions,
    normalizeAdminRulePath,
    normalizeAdminScopePath,
    parseTargetUserId,
    saveTargetUserMcBrowserPolicy,
    serializeAdminPolicyPayload,
    toEditablePolicyRules,
    validateAdminRegexPattern,
    validateAdminScopeInput,
    validateEditablePolicyRule,
    validateTargetUserIdInput,
} from '@/lib/mcbrowser-policy-admin';

Object.assign(globalThis, { TextEncoder, TextDecoder });

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

function createJsonResponse(status: number, payload: unknown): Response {
    return {
        ok: status >= 200 && status < 300,
        status,
        statusText: status === 200 ? 'OK' : 'Error',
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: async () => payload,
    } as unknown as Response;
}

describe('mcbrowser-policy-admin library', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('defaults safe actions off and strips unknown permission keys', () => {
        expect(MCBROWSER_PERMISSION_KEYS).toEqual([
            'read',
            'create',
            'rename',
            'modify',
            'delete',
            'share',
            'download',
            'execute',
        ]);

        const defaults = createDefaultAdminPolicyPermissions();
        expect(Object.keys(defaults)).toEqual([...MCBROWSER_PERMISSION_KEYS]);
        expect(defaults.execute).toBe(false);
        expect(normalizeAdminPolicyPermissions({}).execute).toBe(false);
        expect(normalizeAdminPolicyPermissions({ execute: 'true' }).execute).toBe(false);

        const normalized = normalizeAdminPolicyPermissions({
            read: true,
            create: false,
            rename: true,
            modify: false,
            delete: false,
            share: true,
            download: false,
            execute: true,
            customFlag: true,
        });
        expect(normalized).toEqual({
            read: true,
            create: false,
            rename: true,
            modify: false,
            delete: false,
            share: true,
            download: false,
            execute: true,
        });
        expect(normalized.execute).toBe(true);
        expect('customFlag' in normalized).toBe(false);
    });

    it('validates explicit numeric target user IDs and rejects invalid values', () => {
        expect(parseTargetUserId('42')).toBe(42);
        expect(parseTargetUserId('  7  ')).toBe(7);
        expect(parseTargetUserId(19)).toBe(19);
        expect(validateTargetUserIdInput('105')).toBeNull();

        for (const badId of ['', '   ', '0', '-4', '3.14', '01', 'user-2', 'NaN']) {
            expect(() => parseTargetUserId(badId)).toThrow(McBrowserRequestError);
            expect(validateTargetUserIdInput(badId)).toBeTruthy();
        }
        expect(() => parseTargetUserId(0)).toThrow(McBrowserRequestError);
        expect(() => parseTargetUserId(-1)).toThrow(McBrowserRequestError);
    });

    it('normalizes relative scope paths and rejects host, traversal, wildcard, and reserved scopes', () => {
        expect(normalizeAdminScopePath('')).toBe('');
        expect(normalizeAdminScopePath('tenants//acme/media/')).toBe('tenants/acme/media');
        expect(validateAdminScopeInput('projects/alpha')).toBeNull();

        for (const badScope of [
            '/var/lib/aetherflow',
            '../escape',
            'nested/../../escape',
            './local',
            'dir\\backslash',
            '   ',
            'glob/*',
            'question?',
            '.af-upload-tmp.123',
            'null\0byte',
        ]) {
            expect(() => normalizeAdminScopePath(badScope)).toThrow(McBrowserRequestError);
            expect(validateAdminScopeInput(badScope)).toBeTruthy();
        }
    });

    it('normalizes ordered prefix and regex rules and enforces rule count and regex constraints', () => {
        expect(normalizeAdminRulePath('private//vault/')).toBe('private/vault');
        expect(() => normalizeAdminRulePath('/etc/passwd')).toThrow(McBrowserRequestError);
        expect(() => normalizeAdminRulePath('logs/*.log')).toThrow(McBrowserRequestError);

        expect(validateAdminRegexPattern('^/logs/public-.*\\.log$')).toBe('^/logs/public-.*\\.log$');
        expect(() => validateAdminRegexPattern('')).toThrow(McBrowserRequestError);
        expect(() => validateAdminRegexPattern('[unclosed')).toThrow(McBrowserRequestError);
        expect(() => validateAdminRegexPattern('a'.repeat(2049))).toThrow(McBrowserRequestError);

        const prefixRule = normalizeAdminPathRule({
            ruleId: 'rule-1',
            path: 'team//secret/',
            allow: false,
            regex: false,
            expression: '',
        });
        expect(prefixRule).toEqual({
            path: 'team/secret',
            allow: false,
            regex: false,
        });
        expect('regexp' in prefixRule).toBe(false);

        const regexRule = normalizeAdminPathRule({
            ruleId: 'rule-2',
            path: 'public-logs',
            allow: true,
            regex: true,
            expression: '^/team/secret/public-.*\\.log$',
        });
        expect(regexRule).toEqual({
            path: 'public-logs',
            allow: true,
            regex: true,
            regexp: {
                raw: '^/team/secret/public-.*\\.log$',
            },
        });

        expect(() =>
            normalizeAdminPathRule({
                path: 'docs',
                allow: false,
                regex: false,
                regexp: { raw: '^/docs$' },
            })
        ).toThrow(McBrowserRequestError);

        expect(
            validateEditablePolicyRule({
                ruleId: 'bad-regex',
                path: '[unclosed',
                allow: false,
                regex: true,
                expression: '[unclosed',
            })
        ).toBeTruthy();

        const oversizedRules = Array.from({ length: MAX_ADMIN_POLICY_RULES + 1 }, (_, index) => ({
            path: `folder-${index}`,
            allow: true,
            regex: false,
        }));
        expect(() =>
            serializeAdminPolicyPayload({
                permissions: createDefaultAdminPolicyPermissions(),
                rules: oversizedRules,
                scope: '',
            })
        ).toThrow(McBrowserRequestError);
    });

    it('reorders rules deterministically and converts wire rules into editable rows', () => {
        const wireRules = [
            { path: 'alpha', allow: false, regex: false },
            {
                path: 'beta-regex',
                allow: true,
                regex: true,
                regexp: { raw: '^/alpha/public/.*$' },
            },
            { path: 'gamma', allow: false, regex: false },
        ];

        const editable = toEditablePolicyRules(wireRules);
        expect(editable).toEqual([
            {
                ruleId: 'policy-rule-1',
                path: 'alpha',
                allow: false,
                regex: false,
                expression: '',
            },
            {
                ruleId: 'policy-rule-2',
                path: 'beta-regex',
                allow: true,
                regex: true,
                expression: '^/alpha/public/.*$',
            },
            {
                ruleId: 'policy-rule-3',
                path: 'gamma',
                allow: false,
                regex: false,
                expression: '',
            },
        ]);

        const movedDown = movePolicyRule(editable, 0, 1);
        expect(movedDown.map((item) => item.path)).toEqual(['beta-regex', 'alpha', 'gamma']);

        const movedUp = movePolicyRule(movedDown, 2, 0);
        expect(movedUp.map((item) => item.path)).toEqual(['gamma', 'beta-regex', 'alpha']);
    });

    it('fetches and saves target user policy via GET/PUT /api/v1/auth/mcbrowser/policy/:user_id', async () => {
        const serverDocument = {
            permissions: {
                read: true,
                create: false,
                rename: true,
                modify: false,
                delete: false,
                share: true,
                download: true,
                execute: true,
            },
            rules: [
                {
                    path: 'vault/locked',
                    allow: false,
                    regex: false,
                },
                {
                    path: '^/vault/locked/readme\\.md$',
                    allow: true,
                    regex: true,
                    regexp: { raw: '^/vault/locked/readme\\.md$' },
                },
            ],
            scope: 'org/engineering',
        };

        mockedApiFetch.mockResolvedValueOnce(createJsonResponse(200, serverDocument));

        const abortController = new AbortController();
        const loaded = await fetchTargetUserMcBrowserPolicy('12', abortController.signal);
        expect(mockedApiFetch).toHaveBeenCalledWith(
            `${MCBROWSER_BASE}/policy/12`,
            expect.objectContaining({
                method: 'GET',
                signal: abortController.signal,
            })
        );
        expect(loaded.permissions.execute).toBe(true);
        expect(loaded.scope).toBe('org/engineering');
        expect(loaded.rules).toHaveLength(2);

        mockedApiFetch.mockResolvedValueOnce(
            createJsonResponse(200, {
                ...createDefaultAdminPolicyDocument(),
                permissions: {
                    ...createDefaultAdminPolicyPermissions(),
                    delete: false,
                },
                rules: loaded.rules,
                scope: 'org/engineering',
            })
        );

        const saved = await saveTargetUserMcBrowserPolicy(12, {
            permissions: {
                ...loaded.permissions,
                delete: false,
                execute: true,
            },
            rules: toEditablePolicyRules(loaded.rules),
            scope: 'org//engineering/',
        });

        expect(mockedApiFetch).toHaveBeenLastCalledWith(
            `${MCBROWSER_BASE}/policy/12`,
            expect.objectContaining({
                method: 'PUT',
            })
        );
        const sentInit = mockedApiFetch.mock.calls[1]?.[1];
        const sentPayload = JSON.parse(String(sentInit?.body));
        expect(sentPayload.permissions.execute).toBe(true);
        expect(Object.keys(sentPayload.permissions)).toEqual([...MCBROWSER_PERMISSION_KEYS]);
        expect(sentPayload.scope).toBe('org/engineering');
        expect(sentPayload.rules[0]).toEqual({
            path: 'vault/locked',
            allow: false,
            regex: false,
        });
        expect('regexp' in sentPayload.rules[0]).toBe(false);
        expect(sentPayload.rules[1]).toEqual({
            path: '^/vault/locked/readme\\.md$',
            allow: true,
            regex: true,
            regexp: { raw: '^/vault/locked/readme\\.md$' },
        });
        expect(saved.permissions.delete).toBe(false);
    });
});
