import {
  MCBROWSER_BASE,
  McBrowserRequestError,
  mcbrowserJsonRequest,
} from '@/lib/mcbrowser';
import type { McBrowserPolicyPermissions } from '@/lib/mcbrowser-workspace';

export type McBrowserPermissions = McBrowserPolicyPermissions;
export type McBrowserPermissionFlags = McBrowserPolicyPermissions;

export const MCBROWSER_ACTIONS_URL = `${MCBROWSER_BASE}/actions`;

export const MAX_MCBROWSER_ACTION_BODY_BYTES = 65_536;
export const MAX_MCBROWSER_ACTION_ALGORITHMS = 16;
export const MAX_MCBROWSER_ACTION_SOURCE_PATHS = 4_096;
export const MAX_MCBROWSER_ACTION_PATH_BYTES = 4_096;
export const MAX_MCBROWSER_ACTION_PATH_SEGMENTS = 64;
export const MAX_MCBROWSER_ACTION_SEGMENT_BYTES = 255;

export const MCBROWSER_ACTION_KINDS = [
  'compute_checksums',
  'extract_archive',
  'create_archive',
  'inspect_media_metadata',
] as const;

export type McBrowserActionKind = (typeof MCBROWSER_ACTION_KINDS)[number];

export const MCBROWSER_CHECKSUM_ALGORITHMS = [
  'md5',
  'sha1',
  'sha256',
  'sha512',
] as const;

export type McBrowserChecksumAlgorithm = (typeof MCBROWSER_CHECKSUM_ALGORITHMS)[number];

export const MCBROWSER_ACTION_ARCHIVE_FORMATS = [
  'zip',
  'tar',
  'targz',
  'tarbz2',
  'tarxz',
  'tarlz4',
  'tarsz',
  'tarbr',
  'tarzst',
] as const;

export type McBrowserActionArchiveFormat = (typeof MCBROWSER_ACTION_ARCHIVE_FORMATS)[number];

export interface McBrowserActionArchiveFormatDescriptor {
  format: McBrowserActionArchiveFormat;
  label: string;
  extension: string;
  aliases: readonly string[];
}

export const MCBROWSER_ACTION_ARCHIVE_FORMAT_DESCRIPTORS: readonly McBrowserActionArchiveFormatDescriptor[] = [
  { format: 'zip', label: 'ZIP (.zip)', extension: '.zip', aliases: ['zip', '.zip'] },
  { format: 'tar', label: 'TAR (.tar)', extension: '.tar', aliases: ['tar', '.tar'] },
  {
    format: 'targz',
    label: 'TAR.GZ (.tar.gz / .tgz)',
    extension: '.tar.gz',
    aliases: ['targz', 'tar.gz', '.tar.gz', 'tgz', '.tgz'],
  },
  {
    format: 'tarbz2',
    label: 'TAR.BZ2 (.tar.bz2 / .tbz2)',
    extension: '.tar.bz2',
    aliases: ['tarbz2', 'tar.bz2', '.tar.bz2', 'tbz2', '.tbz2'],
  },
  {
    format: 'tarxz',
    label: 'TAR.XZ (.tar.xz / .txz)',
    extension: '.tar.xz',
    aliases: ['tarxz', 'tar.xz', '.tar.xz', 'txz', '.txz'],
  },
  {
    format: 'tarlz4',
    label: 'TAR.LZ4 (.tar.lz4 / .tlz4)',
    extension: '.tar.lz4',
    aliases: ['tarlz4', 'tar.lz4', '.tar.lz4', 'tlz4', '.tlz4'],
  },
  {
    format: 'tarsz',
    label: 'TAR.SZ (.tar.sz / .tsz)',
    extension: '.tar.sz',
    aliases: ['tarsz', 'tar.sz', '.tar.sz', 'tsz', '.tsz'],
  },
  {
    format: 'tarbr',
    label: 'TAR.BR (.tar.br / .tbr)',
    extension: '.tar.br',
    aliases: ['tarbr', 'tar.br', '.tar.br', 'tbr', '.tbr'],
  },
  {
    format: 'tarzst',
    label: 'TAR.ZST (.tar.zst / .tzst)',
    extension: '.tar.zst',
    aliases: ['tarzst', 'tar.zst', '.tar.zst', 'tzst', '.tzst'],
  },
] as const;

export interface McBrowserComputeChecksumsActionRequest {
  action: 'compute_checksums';
  path: string;
  algorithms: McBrowserChecksumAlgorithm[];
}

export interface McBrowserExtractArchiveActionRequest {
  action: 'extract_archive';
  archive_path: string;
  destination_dir: string;
}

export interface McBrowserCreateArchiveActionRequest {
  action: 'create_archive';
  source_paths: string[];
  destination_path: string;
  format: McBrowserActionArchiveFormat;
}

export interface McBrowserInspectMediaMetadataActionRequest {
  action: 'inspect_media_metadata';
  path: string;
}

export type McBrowserActionRequest =
  | McBrowserComputeChecksumsActionRequest
  | McBrowserExtractArchiveActionRequest
  | McBrowserCreateArchiveActionRequest
  | McBrowserInspectMediaMetadataActionRequest;

export interface McBrowserComputeChecksumsActionResponse {
  action: 'compute_checksums';
  success: boolean;
  path: string;
  size: number;
  checksums: Record<string, string>;
}

export interface McBrowserExtractArchiveActionResponse {
  action: 'extract_archive';
  success: boolean;
  archive_path: string;
  destination_dir: string;
  format: McBrowserActionArchiveFormat;
  extracted_files: number;
  extracted_directories: number;
  extracted_bytes: number;
}

export interface McBrowserCreateArchiveActionResponse {
  action: 'create_archive';
  success: boolean;
  destination_path: string;
  format: McBrowserActionArchiveFormat;
  entry_count: number;
  archive_bytes: number;
}

export interface McBrowserActionMediaResolution {
  width: number;
  height: number;
}

export interface McBrowserActionSubtitleTrack {
  path: string;
  name: string;
  label: string;
  language: string | null;
  format: string;
  url: string;
}

export interface McBrowserInspectMediaMetadataActionResponse {
  action: 'inspect_media_metadata';
  success: boolean;
  path: string;
  name: string;
  kind: string;
  content_type: string | null;
  size: number;
  modified: string | null;
  resolution: McBrowserActionMediaResolution | null;
  subtitles: McBrowserActionSubtitleTrack[];
}

export type McBrowserActionResponse =
  | McBrowserComputeChecksumsActionResponse
  | McBrowserExtractArchiveActionResponse
  | McBrowserCreateArchiveActionResponse
  | McBrowserInspectMediaMetadataActionResponse;

export type McBrowserEffectiveActionPermissions = Pick<
  McBrowserPermissionFlags,
  'execute' | 'read' | 'create' | 'download'
>;

export interface McBrowserActionPermissionEvaluation {
  allowed: boolean;
  executeEnabled: boolean;
  missingPermissions: Array<keyof McBrowserEffectiveActionPermissions>;
  reason: string | null;
}

const UTF8_ENCODER = new TextEncoder();

const FORBIDDEN_SHELL_KEYS = new Set([
  'command',
  'cmd',
  'shell',
  'args',
  'argv',
  'binary',
  'executable',
  'script',
  'cwd',
  'workdir',
  'working_directory',
  'env',
]);

function utf8ByteLength(value: string): number {
  return UTF8_ENCODER.encode(value).byteLength;
}

function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function isStagingComponent(segment: string): boolean {
  const lower = segment.toLowerCase();
  return lower.startsWith('.af-upload-tmp.') || lower === '.af-upload-staging';
}

function looksLikeWindowsDriveSegment(segment: string): boolean {
  return /^[a-zA-Z]:/.test(segment);
}

export function normalizeMcBrowserActionRelativePath(
  raw: string,
  fieldName = 'path',
): string {
  if (typeof raw !== 'string') {
    throw new McBrowserRequestError(400, 'INVALID_PATH', `${fieldName} must be a string.`);
  }
  if (raw.includes('\0') || hasControlChar(raw)) {
    throw new McBrowserRequestError(
      400,
      'INVALID_PATH',
      `${fieldName} cannot contain control characters.`,
    );
  }
  if (raw.includes('\\')) {
    throw new McBrowserRequestError(
      400,
      'INVALID_PATH',
      `${fieldName} cannot contain backslashes ('\\').`,
    );
  }
  if (raw.includes('*') || raw.includes('?')) {
    throw new McBrowserRequestError(
      400,
      'INVALID_PATH',
      `${fieldName} cannot contain glob wildcards ('*' or '?').`,
    );
  }

  const trimmed = raw.trim();
  if (!trimmed) {
    throw new McBrowserRequestError(
      400,
      'INVALID_PATH',
      `${fieldName} must be a non-empty relative path.`,
    );
  }
  if (trimmed.startsWith('/')) {
    throw new McBrowserRequestError(
      400,
      'INVALID_PATH',
      `${fieldName} must be a relative path and cannot start with '/'.`,
    );
  }
  if (utf8ByteLength(trimmed) > MAX_MCBROWSER_ACTION_PATH_BYTES) {
    throw new McBrowserRequestError(
      400,
      'INVALID_PATH',
      `${fieldName} exceeds the maximum length of ${MAX_MCBROWSER_ACTION_PATH_BYTES} bytes.`,
    );
  }

  const rawSegments = trimmed.split('/');
  const normalizedSegments: string[] = [];

  for (const seg of rawSegments) {
    if (!seg) {
      continue;
    }
    if (!seg.trim()) {
      throw new McBrowserRequestError(
        400,
        'INVALID_PATH',
        `${fieldName} cannot contain whitespace-only path segments.`,
      );
    }
    if (seg === '.' || seg === '..') {
      throw new McBrowserRequestError(
        400,
        'INVALID_PATH',
        `${fieldName} cannot contain '.' or '..' traversal segments.`,
      );
    }
    if (normalizedSegments.length === 0 && looksLikeWindowsDriveSegment(seg)) {
      throw new McBrowserRequestError(
        400,
        'INVALID_PATH',
        `${fieldName} cannot start with a drive prefix.`,
      );
    }
    if (isStagingComponent(seg)) {
      throw new McBrowserRequestError(
        400,
        'INVALID_PATH',
        `${fieldName} cannot reference internal upload staging paths.`,
      );
    }
    if (utf8ByteLength(seg) > MAX_MCBROWSER_ACTION_SEGMENT_BYTES) {
      throw new McBrowserRequestError(
        400,
        'INVALID_PATH',
        `${fieldName} segment exceeds ${MAX_MCBROWSER_ACTION_SEGMENT_BYTES} bytes.`,
      );
    }
    normalizedSegments.push(seg);
    if (normalizedSegments.length > MAX_MCBROWSER_ACTION_PATH_SEGMENTS) {
      throw new McBrowserRequestError(
        400,
        'INVALID_PATH',
        `${fieldName} exceeds the maximum depth of ${MAX_MCBROWSER_ACTION_PATH_SEGMENTS} segments.`,
      );
    }
  }

  if (normalizedSegments.length === 0) {
    throw new McBrowserRequestError(
      400,
      'INVALID_PATH',
      `${fieldName} must be a non-empty relative path.`,
    );
  }

  const joined = normalizedSegments.join('/');
  if (utf8ByteLength(joined) > MAX_MCBROWSER_ACTION_PATH_BYTES) {
    throw new McBrowserRequestError(
      400,
      'INVALID_PATH',
      `${fieldName} exceeds the maximum length of ${MAX_MCBROWSER_ACTION_PATH_BYTES} bytes.`,
    );
  }
  return joined;
}

export function doMcBrowserActionPathsOverlap(left: string, right: string): boolean {
  const a = normalizeMcBrowserActionRelativePath(left, 'path');
  const b = normalizeMcBrowserActionRelativePath(right, 'path');
  if (a === b) {
    return true;
  }
  return a.startsWith(`${b}/`) || b.startsWith(`${a}/`);
}

export function normalizeMcBrowserChecksumAlgorithm(
  raw: string,
): McBrowserChecksumAlgorithm {
  const normalized = (typeof raw === 'string' ? raw : '').trim().toLowerCase();
  if (
    normalized === 'md5' ||
    normalized === 'sha1' ||
    normalized === 'sha256' ||
    normalized === 'sha512'
  ) {
    return normalized;
  }
  throw new McBrowserRequestError(
    400,
    'UNSUPPORTED_ALGORITHM',
    `Unsupported checksum algorithm '${raw}'. Supported algorithms: md5, sha1, sha256, sha512.`,
  );
}

export function normalizeMcBrowserChecksumAlgorithms(
  algorithms: readonly string[],
): McBrowserChecksumAlgorithm[] {
  if (!Array.isArray(algorithms) || algorithms.length === 0) {
    throw new McBrowserRequestError(
      400,
      'INVALID_ACTION_PAYLOAD',
      'compute_checksums requires at least one algorithm.',
    );
  }
  if (algorithms.length > MAX_MCBROWSER_ACTION_ALGORITHMS) {
    throw new McBrowserRequestError(
      400,
      'INVALID_ACTION_PAYLOAD',
      `compute_checksums supports at most ${MAX_MCBROWSER_ACTION_ALGORITHMS} algorithms per call.`,
    );
  }
  const seen = new Set<McBrowserChecksumAlgorithm>();
  const normalized: McBrowserChecksumAlgorithm[] = [];
  for (const raw of algorithms) {
    const algo = normalizeMcBrowserChecksumAlgorithm(raw);
    if (!seen.has(algo)) {
      seen.add(algo);
      normalized.push(algo);
    }
  }
  return normalized;
}

export function normalizeMcBrowserArchiveFormat(
  raw: string,
): McBrowserActionArchiveFormat {
  const cleaned = (typeof raw === 'string' ? raw : '')
    .trim()
    .toLowerCase()
    .replace(/^\.+/, '');
  switch (cleaned) {
    case 'zip':
      return 'zip';
    case 'tar':
      return 'tar';
    case 'targz':
    case 'tar.gz':
    case 'tgz':
      return 'targz';
    case 'tarbz2':
    case 'tar.bz2':
    case 'tbz2':
      return 'tarbz2';
    case 'tarxz':
    case 'tar.xz':
    case 'txz':
      return 'tarxz';
    case 'tarlz4':
    case 'tar.lz4':
    case 'tlz4':
      return 'tarlz4';
    case 'tarsz':
    case 'tar.sz':
    case 'tsz':
      return 'tarsz';
    case 'tarbr':
    case 'tar.br':
    case 'tbr':
      return 'tarbr';
    case 'tarzst':
    case 'tar.zst':
    case 'tzst':
      return 'tarzst';
    default:
      throw new McBrowserRequestError(
        400,
        'UNSUPPORTED_ARCHIVE_FORMAT',
        `Unsupported archive format '${raw}'. Supported formats: zip, tar, targz, tarbz2, tarxz, tarlz4, tarsz, tarbr, tarzst.`,
      );
  }
}

export function detectMcBrowserArchiveFormatFromPath(
  path: string,
): McBrowserActionArchiveFormat | null {
  const lower = (typeof path === 'string' ? path : '').trim().toLowerCase();
  if (!lower) {
    return null;
  }
  if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) {
    return 'targz';
  }
  if (lower.endsWith('.tar.bz2') || lower.endsWith('.tbz2')) {
    return 'tarbz2';
  }
  if (lower.endsWith('.tar.xz') || lower.endsWith('.txz')) {
    return 'tarxz';
  }
  if (lower.endsWith('.tar.lz4') || lower.endsWith('.tlz4')) {
    return 'tarlz4';
  }
  if (lower.endsWith('.tar.sz') || lower.endsWith('.tsz')) {
    return 'tarsz';
  }
  if (lower.endsWith('.tar.br') || lower.endsWith('.tbr')) {
    return 'tarbr';
  }
  if (lower.endsWith('.tar.zst') || lower.endsWith('.tzst')) {
    return 'tarzst';
  }
  if (lower.endsWith('.zip')) {
    return 'zip';
  }
  if (lower.endsWith('.tar')) {
    return 'tar';
  }
  return null;
}

export function getMcBrowserArchiveFormatDescriptor(
  format: McBrowserActionArchiveFormat,
): McBrowserActionArchiveFormatDescriptor {
  const found = MCBROWSER_ACTION_ARCHIVE_FORMAT_DESCRIPTORS.find(
    (item) => item.format === format,
  );
  if (!found) {
    throw new McBrowserRequestError(
      400,
      'UNSUPPORTED_ARCHIVE_FORMAT',
      `Unsupported archive format '${String(format)}'.`,
    );
  }
  return found;
}

export function evaluateMcBrowserActionPermissions(
  action: McBrowserActionKind,
  permissions?: Partial<McBrowserEffectiveActionPermissions> | null,
): McBrowserActionPermissionEvaluation {
  const executeEnabled = permissions?.execute === true;
  const readEnabled = permissions?.read === true;
  const createEnabled = permissions?.create === true;
  const downloadEnabled = permissions?.download === true;

  const missing: Array<keyof McBrowserEffectiveActionPermissions> = [];
  if (!executeEnabled) {
    missing.push('execute');
  }
  if (!readEnabled) {
    missing.push('read');
  }
  if (action === 'extract_archive' && !createEnabled) {
    missing.push('create');
  }
  if (action === 'create_archive') {
    if (!downloadEnabled) {
      missing.push('download');
    }
    if (!createEnabled) {
      missing.push('create');
    }
  }

  if (missing.length === 0) {
    return {
      allowed: true,
      executeEnabled: true,
      missingPermissions: [],
      reason: null,
    };
  }

  if (!executeEnabled) {
    return {
      allowed: false,
      executeEnabled: false,
      missingPermissions: missing,
      reason:
        'Execute permission is off by default and must be explicitly granted by policy to run native actions.',
    };
  }

  return {
    allowed: false,
    executeEnabled: true,
    missingPermissions: missing,
    reason: `Missing required permission(s) for ${action}: ${missing.join(', ')}.`,
  };
}

export function canExecuteMcBrowserAction(
  action: McBrowserActionKind,
  permissions?: Partial<McBrowserEffectiveActionPermissions> | null,
): boolean {
  return evaluateMcBrowserActionPermissions(action, permissions).allowed;
}

function assertAllowedKeys(
  payload: Record<string, unknown>,
  allowedKeys: readonly string[],
  actionName: string,
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(payload)) {
    if (FORBIDDEN_SHELL_KEYS.has(key.toLowerCase())) {
      throw new McBrowserRequestError(
        400,
        'INVALID_ACTION_PAYLOAD',
        `Arbitrary shell or command execution field '${key}' is not permitted.`,
      );
    }
    if (!allowed.has(key)) {
      throw new McBrowserRequestError(
        400,
        'INVALID_ACTION_PAYLOAD',
        `Unknown field '${key}' in ${actionName} action payload.`,
      );
    }
  }
}

export function validateAndNormalizeMcBrowserActionRequest(
  request: McBrowserActionRequest,
): McBrowserActionRequest {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new McBrowserRequestError(
      400,
      'INVALID_ACTION_PAYLOAD',
      'Action request must be a JSON object.',
    );
  }

  const rawRecord = request as unknown as Record<string, unknown>;
  const action = rawRecord.action;

  if (typeof action !== 'string' || !MCBROWSER_ACTION_KINDS.includes(action as McBrowserActionKind)) {
    throw new McBrowserRequestError(
      400,
      'INVALID_ACTION_PAYLOAD',
      'Unsupported or missing McBrowser native action variant.',
    );
  }

  let normalized: McBrowserActionRequest;

  switch (action as McBrowserActionKind) {
    case 'compute_checksums': {
      assertAllowedKeys(rawRecord, ['action', 'path', 'algorithms'], 'compute_checksums');
      const path = normalizeMcBrowserActionRelativePath(
        rawRecord.path as string,
        'path',
      );
      const algorithms = normalizeMcBrowserChecksumAlgorithms(
        rawRecord.algorithms as string[],
      );
      normalized = {
        action: 'compute_checksums',
        path,
        algorithms,
      };
      break;
    }
    case 'extract_archive': {
      assertAllowedKeys(
        rawRecord,
        ['action', 'archive_path', 'destination_dir'],
        'extract_archive',
      );
      const archivePath = normalizeMcBrowserActionRelativePath(
        rawRecord.archive_path as string,
        'archive_path',
      );
      const destinationDir = normalizeMcBrowserActionRelativePath(
        rawRecord.destination_dir as string,
        'destination_dir',
      );
      if (!detectMcBrowserArchiveFormatFromPath(archivePath)) {
        throw new McBrowserRequestError(
          400,
          'UNSUPPORTED_ARCHIVE_FORMAT',
          `Unsupported archive extension on '${archivePath}'.`,
        );
      }
      if (doMcBrowserActionPathsOverlap(archivePath, destinationDir)) {
        throw new McBrowserRequestError(
          400,
          'ARCHIVE_PATH_OVERLAP',
          'extract_archive destination_dir must not overlap archive_path.',
        );
      }
      normalized = {
        action: 'extract_archive',
        archive_path: archivePath,
        destination_dir: destinationDir,
      };
      break;
    }
    case 'create_archive': {
      assertAllowedKeys(
        rawRecord,
        ['action', 'source_paths', 'destination_path', 'format'],
        'create_archive',
      );
      const rawSources = rawRecord.source_paths;
      if (!Array.isArray(rawSources) || rawSources.length === 0) {
        throw new McBrowserRequestError(
          400,
          'INVALID_ACTION_PAYLOAD',
          'create_archive requires at least one source path.',
        );
      }
      if (rawSources.length > MAX_MCBROWSER_ACTION_SOURCE_PATHS) {
        throw new McBrowserRequestError(
          400,
          'INVALID_ACTION_PAYLOAD',
          `create_archive supports at most ${MAX_MCBROWSER_ACTION_SOURCE_PATHS} source paths per call.`,
        );
      }
      const destinationPath = normalizeMcBrowserActionRelativePath(
        rawRecord.destination_path as string,
        'destination_path',
      );
      const format = normalizeMcBrowserArchiveFormat(rawRecord.format as string);

      const seenSources = new Set<string>();
      const sourcePaths: string[] = [];
      for (const rawSource of rawSources) {
        const normalizedSource = normalizeMcBrowserActionRelativePath(
          rawSource as string,
          'source_paths',
        );
        if (doMcBrowserActionPathsOverlap(normalizedSource, destinationPath)) {
          throw new McBrowserRequestError(
            400,
            'ARCHIVE_PATH_OVERLAP',
            `destination_path '${destinationPath}' overlaps with source path '${normalizedSource}'.`,
          );
        }
        if (!seenSources.has(normalizedSource)) {
          seenSources.add(normalizedSource);
          sourcePaths.push(normalizedSource);
        }
      }

      normalized = {
        action: 'create_archive',
        source_paths: sourcePaths,
        destination_path: destinationPath,
        format,
      };
      break;
    }
    case 'inspect_media_metadata': {
      assertAllowedKeys(rawRecord, ['action', 'path'], 'inspect_media_metadata');
      const path = normalizeMcBrowserActionRelativePath(
        rawRecord.path as string,
        'path',
      );
      normalized = {
        action: 'inspect_media_metadata',
        path,
      };
      break;
    }
  }

  const serializedBytes = utf8ByteLength(JSON.stringify(normalized));
  if (serializedBytes > MAX_MCBROWSER_ACTION_BODY_BYTES) {
    throw new McBrowserRequestError(
      413,
      'PAYLOAD_TOO_LARGE',
      `Action request exceeds maximum body size of ${MAX_MCBROWSER_ACTION_BODY_BYTES} bytes.`,
    );
  }

  return normalized;
}

export async function dispatchMcBrowserAction<
  TResponse extends McBrowserActionResponse = McBrowserActionResponse,
>(
  request: McBrowserActionRequest,
  signal?: AbortSignal,
): Promise<TResponse> {
  const normalized = validateAndNormalizeMcBrowserActionRequest(request);
  return mcbrowserJsonRequest<TResponse>(
    MCBROWSER_ACTIONS_URL,
    {
      method: 'POST',
      body: JSON.stringify(normalized),
      signal,
    },
    `Failed to execute McBrowser ${normalized.action} action`,
  );
}

export async function computeMcBrowserActionChecksums(
  params: {
    path: string;
    algorithms: readonly McBrowserChecksumAlgorithm[];
  },
  signal?: AbortSignal,
): Promise<McBrowserComputeChecksumsActionResponse> {
  return dispatchMcBrowserAction<McBrowserComputeChecksumsActionResponse>(
    {
      action: 'compute_checksums',
      path: params.path,
      algorithms: [...params.algorithms],
    },
    signal,
  );
}

export async function extractMcBrowserArchiveAction(
  params: {
    archive_path: string;
    destination_dir: string;
  },
  signal?: AbortSignal,
): Promise<McBrowserExtractArchiveActionResponse> {
  return dispatchMcBrowserAction<McBrowserExtractArchiveActionResponse>(
    {
      action: 'extract_archive',
      archive_path: params.archive_path,
      destination_dir: params.destination_dir,
    },
    signal,
  );
}

export async function createMcBrowserArchiveAction(
  params: {
    source_paths: readonly string[];
    destination_path: string;
    format: McBrowserActionArchiveFormat;
  },
  signal?: AbortSignal,
): Promise<McBrowserCreateArchiveActionResponse> {
  return dispatchMcBrowserAction<McBrowserCreateArchiveActionResponse>(
    {
      action: 'create_archive',
      source_paths: [...params.source_paths],
      destination_path: params.destination_path,
      format: params.format,
    },
    signal,
  );
}

export async function inspectMcBrowserMediaMetadataAction(
  params: {
    path: string;
  },
  signal?: AbortSignal,
): Promise<McBrowserInspectMediaMetadataActionResponse> {
  return dispatchMcBrowserAction<McBrowserInspectMediaMetadataActionResponse>(
    {
      action: 'inspect_media_metadata',
      path: params.path,
    },
    signal,
  );
}
