import {
    MCBROWSER_BASE,
    McBrowserRequestError,
    mcbrowserJsonRequest,
} from '@/lib/mcbrowser';

export const MAX_ADMIN_POLICY_RULES = 256;
export const MAX_ADMIN_RULE_EXPRESSION_BYTES = 2048;
export const MAX_ADMIN_RELATIVE_PATH_BYTES = 4096;
export const MAX_ADMIN_RELATIVE_PATH_SEGMENTS = 64;
export const MAX_ADMIN_RELATIVE_SEGMENT_BYTES = 255;

export const MCBROWSER_PERMISSION_KEYS = [
    'read',
    'create',
    'rename',
    'modify',
    'delete',
    'share',
    'download',
    'execute',
] as const;

export type McBrowserPermissionKey = (typeof MCBROWSER_PERMISSION_KEYS)[number];

export interface McBrowserAdminPolicyPermissions {
    read: boolean;
    create: boolean;
    rename: boolean;
    modify: boolean;
    delete: boolean;
    share: boolean;
    download: boolean;
    execute: boolean;
}

export interface McBrowserAdminRuleExpression {
    raw: string;
}

export interface McBrowserAdminPathRule {
    path: string;
    allow: boolean;
    regex: boolean;
    regexp?: McBrowserAdminRuleExpression;
}

export interface McBrowserAdminPolicyDocument {
    permissions: McBrowserAdminPolicyPermissions;
    rules: McBrowserAdminPathRule[];
    scope: string;
}

export interface McBrowserEditablePolicyRule {
    ruleId: string;
    path: string;
    allow: boolean;
    regex: boolean;
    expression: string;
}

export type McBrowserAdminPolicyPermissionsInput =
    | McBrowserAdminPolicyPermissions
    | Partial<McBrowserAdminPolicyPermissions>
    | Record<string, unknown>;

export interface McBrowserAdminPolicyInput {
    permissions: McBrowserAdminPolicyPermissionsInput;
    rules: ReadonlyArray<McBrowserAdminPathRule | McBrowserEditablePolicyRule>;
    scope: string;
}

function utf8ByteLength(value: string): number {
    if (typeof TextEncoder !== 'undefined') {
        return new TextEncoder().encode(value).length;
    }
    return Buffer.byteLength(value, 'utf8');
}

function containsControlCharacters(value: string): boolean {
    for (let index = 0; index < value.length; index += 1) {
        const codePoint = value.charCodeAt(index);
        if (codePoint <= 0x1f || codePoint === 0x7f) {
            return true;
        }
    }
    return false;
}

export function createDefaultAdminPolicyPermissions(): McBrowserAdminPolicyPermissions {
    return {
        read: true,
        create: true,
        rename: true,
        modify: true,
        delete: true,
        share: true,
        download: true,
        execute: false,
    };
}

export function createDefaultAdminPolicyDocument(): McBrowserAdminPolicyDocument {
    return {
        permissions: createDefaultAdminPolicyPermissions(),
        rules: [],
        scope: '',
    };
}

export function parseTargetUserId(rawUserId: string | number | null | undefined): number {
    if (typeof rawUserId === 'number') {
        if (
            !Number.isSafeInteger(rawUserId) ||
            rawUserId <= 0
        ) {
            throw new McBrowserRequestError(
                400,
                'INVALID_TARGET_USER_ID',
                'Target user ID must be a positive integer.'
            );
        }
        return rawUserId;
    }

    const trimmed = typeof rawUserId === 'string' ? rawUserId.trim() : '';
    if (!/^[1-9]\d*$/.test(trimmed)) {
        throw new McBrowserRequestError(
            400,
            'INVALID_TARGET_USER_ID',
            'Target user ID must be a positive integer.'
        );
    }

    const parsed = Number(trimmed);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        throw new McBrowserRequestError(
            400,
            'INVALID_TARGET_USER_ID',
            'Target user ID exceeds the supported numeric range.'
        );
    }

    return parsed;
}

export function validateTargetUserIdInput(rawUserId: string): string | null {
    try {
        parseTargetUserId(rawUserId);
        return null;
    } catch (error) {
        if (error instanceof Error) {
            return error.message;
        }
        return 'Target user ID must be a positive integer.';
    }
}

export function normalizeAdminPolicyPermissions(
    rawPermissions?: McBrowserAdminPolicyPermissionsInput | null
): McBrowserAdminPolicyPermissions {
    const defaults = createDefaultAdminPolicyPermissions();
    if (!rawPermissions || typeof rawPermissions !== 'object') {
        return defaults;
    }
    const candidate = rawPermissions as Partial<Record<McBrowserPermissionKey, unknown>>;
    return {
        read: typeof candidate.read === 'boolean' ? candidate.read : defaults.read,
        create: typeof candidate.create === 'boolean' ? candidate.create : defaults.create,
        rename: typeof candidate.rename === 'boolean' ? candidate.rename : defaults.rename,
        modify: typeof candidate.modify === 'boolean' ? candidate.modify : defaults.modify,
        delete: typeof candidate.delete === 'boolean' ? candidate.delete : defaults.delete,
        share: typeof candidate.share === 'boolean' ? candidate.share : defaults.share,
        download:
            typeof candidate.download === 'boolean'
                ? candidate.download
                : defaults.download,
        execute: typeof candidate.execute === 'boolean' ? candidate.execute : defaults.execute,
    };
}

function normalizeValidatedRelativeSegments(
    rawValue: string,
    allowEmpty: boolean,
    errorCode: string,
    fieldLabel: string
): string {
    if (rawValue.length === 0) {
        if (allowEmpty) {
            return '';
        }
        throw new McBrowserRequestError(400, errorCode, `${fieldLabel} is required.`);
    }

    if (rawValue.trim().length === 0) {
        throw new McBrowserRequestError(
            400,
            errorCode,
            `Invalid ${fieldLabel.toLowerCase()}: whitespace-only paths are not allowed.`
        );
    }

    if (rawValue.includes('*') || rawValue.includes('?')) {
        throw new McBrowserRequestError(
            400,
            errorCode,
            `Invalid ${fieldLabel.toLowerCase()}: wildcard characters ('*', '?') are not allowed.`
        );
    }

    if (containsControlCharacters(rawValue)) {
        throw new McBrowserRequestError(
            400,
            errorCode,
            `Invalid ${fieldLabel.toLowerCase()}: control characters are not allowed.`
        );
    }

    if (rawValue.startsWith('/') || rawValue.includes('\\')) {
        throw new McBrowserRequestError(
            400,
            errorCode,
            `Invalid ${fieldLabel.toLowerCase()}: absolute or backslash paths are not allowed.`
        );
    }

    const segments = rawValue.split('/').filter((segment) => segment.length > 0);
    if (segments.length === 0) {
        throw new McBrowserRequestError(
            400,
            errorCode,
            `Invalid ${fieldLabel.toLowerCase()}: empty path segment is not allowed.`
        );
    }

    if (segments.length > MAX_ADMIN_RELATIVE_PATH_SEGMENTS) {
        throw new McBrowserRequestError(
            400,
            errorCode,
            `Invalid ${fieldLabel.toLowerCase()}: path exceeds maximum depth of ${MAX_ADMIN_RELATIVE_PATH_SEGMENTS} segments.`
        );
    }

    for (const segment of segments) {
        if (segment === '.' || segment === '..') {
            throw new McBrowserRequestError(
                400,
                errorCode,
                `Invalid ${fieldLabel.toLowerCase()}: traversal segments are not allowed.`
            );
        }
        if (segment.startsWith('.af-upload-tmp.')) {
            throw new McBrowserRequestError(
                400,
                errorCode,
                `Invalid ${fieldLabel.toLowerCase()}: reserved temporary filename is not allowed.`
            );
        }
        if (segment.trim().length === 0) {
            throw new McBrowserRequestError(
                400,
                errorCode,
                `Invalid ${fieldLabel.toLowerCase()}: whitespace-only path segment is not allowed.`
            );
        }
        if (utf8ByteLength(segment) > MAX_ADMIN_RELATIVE_SEGMENT_BYTES) {
            throw new McBrowserRequestError(
                400,
                errorCode,
                `Invalid ${fieldLabel.toLowerCase()}: path segment exceeds ${MAX_ADMIN_RELATIVE_SEGMENT_BYTES} bytes.`
            );
        }
    }

    const normalized = segments.join('/');
    if (utf8ByteLength(normalized) > MAX_ADMIN_RELATIVE_PATH_BYTES) {
        throw new McBrowserRequestError(
            400,
            errorCode,
            `Invalid ${fieldLabel.toLowerCase()}: path exceeds maximum length of ${MAX_ADMIN_RELATIVE_PATH_BYTES} bytes.`
        );
    }

    return normalized;
}

export function normalizeAdminScopePath(rawScope: string | null | undefined): string {
    const scopeValue = rawScope ?? '';
    if (scopeValue.length === 0) {
        return '';
    }
    return normalizeValidatedRelativeSegments(scopeValue, true, 'INVALID_SCOPE', 'Scope');
}

export function validateAdminScopeInput(rawScope: string): string | null {
    try {
        normalizeAdminScopePath(rawScope);
        return null;
    } catch (error) {
        if (error instanceof Error) {
            return error.message;
        }
        return 'Invalid scope path.';
    }
}

export function normalizeAdminRulePath(rawPath: string | null | undefined): string {
    const pathValue = rawPath ?? '';
    if (pathValue.length === 0) {
        return '';
    }
    return normalizeValidatedRelativeSegments(pathValue, true, 'INVALID_RULE_PATH', 'Rule path');
}

export function validateAdminRegexPattern(rawExpression: string | null | undefined): string {
    const expressionValue = rawExpression ?? '';
    const byteLength = utf8ByteLength(expressionValue);
    if (byteLength === 0 || byteLength > MAX_ADMIN_RULE_EXPRESSION_BYTES) {
        throw new McBrowserRequestError(
            400,
            'INVALID_RULE_REGEX',
            `Rule expression must contain 1..${MAX_ADMIN_RULE_EXPRESSION_BYTES} bytes.`
        );
    }
    if (expressionValue.includes('\0')) {
        throw new McBrowserRequestError(
            400,
            'INVALID_RULE_REGEX',
            'Rule expression cannot contain NUL characters.'
        );
    }
    try {
        new RegExp(expressionValue);
    } catch {
        throw new McBrowserRequestError(
            400,
            'INVALID_RULE_REGEX',
            'Invalid regular expression syntax in rule.'
        );
    }
    return expressionValue;
}

function isEditableRule(
    rule: McBrowserAdminPathRule | McBrowserEditablePolicyRule
): rule is McBrowserEditablePolicyRule {
    return 'expression' in rule && typeof rule.expression === 'string';
}

export function normalizeAdminPathRule(
    rawRule: McBrowserAdminPathRule | McBrowserEditablePolicyRule
): McBrowserAdminPathRule {
    const allowFlag = Boolean(rawRule.allow);
    const regexFlag = Boolean(rawRule.regex);

    if (regexFlag) {
        const candidateExpression = isEditableRule(rawRule)
            ? rawRule.expression.length > 0
                ? rawRule.expression
                : rawRule.path
            : rawRule.regexp?.raw ?? rawRule.path;
        const validatedExpression = validateAdminRegexPattern(candidateExpression);
        const rulePath = rawRule.path.length > 0 ? rawRule.path : validatedExpression;
        return {
            path: rulePath,
            allow: allowFlag,
            regex: true,
            regexp: {
                raw: validatedExpression,
            },
        };
    }

    if (!isEditableRule(rawRule) && rawRule.regexp !== undefined && rawRule.regexp !== null) {
        throw new McBrowserRequestError(
            400,
            'INVALID_RULE_REGEX',
            'A rule expression requires regex=true.'
        );
    }

    if (isEditableRule(rawRule) && rawRule.expression.trim().length > 0) {
        throw new McBrowserRequestError(
            400,
            'INVALID_RULE_REGEX',
            'A rule expression requires regex=true.'
        );
    }

    const normalizedPath = normalizeAdminRulePath(rawRule.path);
    return {
        path: normalizedPath,
        allow: allowFlag,
        regex: false,
    };
}

export function validateEditablePolicyRule(rule: McBrowserEditablePolicyRule): string | null {
    try {
        normalizeAdminPathRule(rule);
        return null;
    } catch (error) {
        if (error instanceof Error) {
            return error.message;
        }
        return 'Invalid policy rule.';
    }
}

export function serializeAdminPolicyPayload(
    input: McBrowserAdminPolicyInput
): McBrowserAdminPolicyDocument {
    if (input.rules.length > MAX_ADMIN_POLICY_RULES) {
        throw new McBrowserRequestError(
            400,
            'TOO_MANY_RULES',
            `Policy cannot contain more than ${MAX_ADMIN_POLICY_RULES} path rules.`
        );
    }

    const permissions = normalizeAdminPolicyPermissions(input.permissions);
    const scope = normalizeAdminScopePath(input.scope);
    const normalizedRules = input.rules.map((rule) => normalizeAdminPathRule(rule));

    return {
        permissions,
        rules: normalizedRules,
        scope,
    };
}

export function toEditablePolicyRules(
    rules: ReadonlyArray<McBrowserAdminPathRule> | null | undefined
): McBrowserEditablePolicyRule[] {
    if (!rules || !Array.isArray(rules)) {
        return [];
    }
    return rules.map((rule, index) => {
        const isRegex = Boolean(rule.regex);
        const expressionText = isRegex ? rule.regexp?.raw ?? rule.path ?? '' : '';
        return {
            ruleId: `policy-rule-${index + 1}`,
            path: rule.path ?? '',
            allow: Boolean(rule.allow),
            regex: isRegex,
            expression: expressionText,
        };
    });
}

export function movePolicyRule<RuleItem>(
    rules: ReadonlyArray<RuleItem>,
    fromIndex: number,
    toIndex: number
): RuleItem[] {
    if (
        fromIndex < 0 ||
        toIndex < 0 ||
        fromIndex >= rules.length ||
        toIndex >= rules.length ||
        fromIndex === toIndex
    ) {
        return [...rules];
    }
    const nextRules = [...rules];
    const [movedItem] = nextRules.splice(fromIndex, 1);
    nextRules.splice(toIndex, 0, movedItem);
    return nextRules;
}

export async function fetchTargetUserMcBrowserPolicy(
    targetUserId: number | string,
    signal?: AbortSignal
): Promise<McBrowserAdminPolicyDocument> {
    const validatedUserId = parseTargetUserId(targetUserId);
    const rawDocument = await mcbrowserJsonRequest<McBrowserAdminPolicyDocument>(
        `${MCBROWSER_BASE}/policy/${encodeURIComponent(String(validatedUserId))}`,
        {
            method: 'GET',
            signal,
        },
        `Failed to load McBrowser policy for user #${validatedUserId}.`
    );

    return serializeAdminPolicyPayload({
        permissions: rawDocument?.permissions ?? createDefaultAdminPolicyPermissions(),
        rules: Array.isArray(rawDocument?.rules) ? rawDocument.rules : [],
        scope: typeof rawDocument?.scope === 'string' ? rawDocument.scope : '',
    });
}

export async function saveTargetUserMcBrowserPolicy(
    targetUserId: number | string,
    policy: McBrowserAdminPolicyInput,
    signal?: AbortSignal
): Promise<McBrowserAdminPolicyDocument> {
    const validatedUserId = parseTargetUserId(targetUserId);
    const payload = serializeAdminPolicyPayload(policy);
    const rawSaved = await mcbrowserJsonRequest<McBrowserAdminPolicyDocument>(
        `${MCBROWSER_BASE}/policy/${encodeURIComponent(String(validatedUserId))}`,
        {
            method: 'PUT',
            body: JSON.stringify(payload),
            signal,
        },
        `Failed to save McBrowser policy for user #${validatedUserId}.`
    );

    return serializeAdminPolicyPayload({
        permissions: rawSaved?.permissions ?? payload.permissions,
        rules: Array.isArray(rawSaved?.rules) ? rawSaved.rules : payload.rules,
        scope: typeof rawSaved?.scope === 'string' ? rawSaved.scope : payload.scope,
    });
}
