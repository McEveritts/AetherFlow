import { TextEncoder, TextDecoder } from 'util';
Object.assign(globalThis, { TextEncoder, TextDecoder });

import { apiFetch } from '@/lib/fetcher';
import { MCBROWSER_BASE, McBrowserRequestError } from '@/lib/mcbrowser';
import {
  MCBROWSER_ACTIONS_URL,
  MCBROWSER_ACTION_ARCHIVE_FORMATS,
  MCBROWSER_ACTION_ARCHIVE_FORMAT_DESCRIPTORS,
  MCBROWSER_CHECKSUM_ALGORITHMS,
  canExecuteMcBrowserAction,
  computeMcBrowserActionChecksums,
  createMcBrowserArchiveAction,
  detectMcBrowserArchiveFormatFromPath,
  dispatchMcBrowserAction,
  doMcBrowserActionPathsOverlap,
  evaluateMcBrowserActionPermissions,
  extractMcBrowserArchiveAction,
  getMcBrowserArchiveFormatDescriptor,
  inspectMcBrowserMediaMetadataAction,
  normalizeMcBrowserActionRelativePath,
  normalizeMcBrowserArchiveFormat,
  normalizeMcBrowserChecksumAlgorithms,
  validateAndNormalizeMcBrowserActionRequest,
  type McBrowserActionRequest,
} from '@/lib/mcbrowser-actions';

jest.mock('@/lib/fetcher', () => ({
  apiFetch: jest.fn(),
}));

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

function mockJsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

describe('mcbrowser-actions client library', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('exposes exact endpoint and all 9 archive formats plus 4 checksum algorithms', () => {
    expect(MCBROWSER_ACTIONS_URL).toBe(`${MCBROWSER_BASE}/actions`);
    expect(MCBROWSER_CHECKSUM_ALGORITHMS).toEqual([
      'md5',
      'sha1',
      'sha256',
      'sha512',
    ]);
    expect(MCBROWSER_ACTION_ARCHIVE_FORMATS).toEqual([
      'zip',
      'tar',
      'targz',
      'tarbz2',
      'tarxz',
      'tarlz4',
      'tarsz',
      'tarbr',
      'tarzst',
    ]);
    expect(MCBROWSER_ACTION_ARCHIVE_FORMAT_DESCRIPTORS).toHaveLength(9);
    for (const fmt of MCBROWSER_ACTION_ARCHIVE_FORMATS) {
      expect(getMcBrowserArchiveFormatDescriptor(fmt).format).toBe(fmt);
    }
  });

  test('normalizes archive format canonical identifiers and aliases', () => {
    expect(normalizeMcBrowserArchiveFormat('zip')).toBe('zip');
    expect(normalizeMcBrowserArchiveFormat('.ZIP')).toBe('zip');
    expect(normalizeMcBrowserArchiveFormat('tar')).toBe('tar');
    expect(normalizeMcBrowserArchiveFormat('targz')).toBe('targz');
    expect(normalizeMcBrowserArchiveFormat('tar.gz')).toBe('targz');
    expect(normalizeMcBrowserArchiveFormat('.tgz')).toBe('targz');
    expect(normalizeMcBrowserArchiveFormat('tarbz2')).toBe('tarbz2');
    expect(normalizeMcBrowserArchiveFormat('tar.bz2')).toBe('tarbz2');
    expect(normalizeMcBrowserArchiveFormat('tbz2')).toBe('tarbz2');
    expect(normalizeMcBrowserArchiveFormat('tarxz')).toBe('tarxz');
    expect(normalizeMcBrowserArchiveFormat('tar.xz')).toBe('tarxz');
    expect(normalizeMcBrowserArchiveFormat('txz')).toBe('tarxz');
    expect(normalizeMcBrowserArchiveFormat('tarlz4')).toBe('tarlz4');
    expect(normalizeMcBrowserArchiveFormat('tar.lz4')).toBe('tarlz4');
    expect(normalizeMcBrowserArchiveFormat('tlz4')).toBe('tarlz4');
    expect(normalizeMcBrowserArchiveFormat('tarsz')).toBe('tarsz');
    expect(normalizeMcBrowserArchiveFormat('tar.sz')).toBe('tarsz');
    expect(normalizeMcBrowserArchiveFormat('tsz')).toBe('tarsz');
    expect(normalizeMcBrowserArchiveFormat('tarbr')).toBe('tarbr');
    expect(normalizeMcBrowserArchiveFormat('tar.br')).toBe('tarbr');
    expect(normalizeMcBrowserArchiveFormat('tbr')).toBe('tarbr');
    expect(normalizeMcBrowserArchiveFormat('tarzst')).toBe('tarzst');
    expect(normalizeMcBrowserArchiveFormat('tar.zst')).toBe('tarzst');
    expect(normalizeMcBrowserArchiveFormat('tzst')).toBe('tarzst');

    expect(() => normalizeMcBrowserArchiveFormat('rar')).toThrow(McBrowserRequestError);
    expect(detectMcBrowserArchiveFormatFromPath('releases/bundle.tar.zst')).toBe('tarzst');
    expect(detectMcBrowserArchiveFormatFromPath('releases/bundle.tlz4')).toBe('tarlz4');
    expect(detectMcBrowserArchiveFormatFromPath('releases/bundle.tsz')).toBe('tarsz');
    expect(detectMcBrowserArchiveFormatFromPath('releases/bundle.tbr')).toBe('tarbr');
    expect(detectMcBrowserArchiveFormatFromPath('releases/notes.txt')).toBeNull();
  });

  test('normalizes relative paths and rejects root, traversal, staging, wildcards, and drive prefixes', () => {
    expect(normalizeMcBrowserActionRelativePath('  docs//guides/readme.md  ')).toBe(
      'docs/guides/readme.md',
    );
    expect(() => normalizeMcBrowserActionRelativePath('')).toThrow(McBrowserRequestError);
    expect(() => normalizeMcBrowserActionRelativePath('/etc/passwd')).toThrow(
      McBrowserRequestError,
    );
    expect(() => normalizeMcBrowserActionRelativePath('docs/../secret.txt')).toThrow(
      McBrowserRequestError,
    );
    expect(() => normalizeMcBrowserActionRelativePath('docs\\file.txt')).toThrow(
      McBrowserRequestError,
    );
    expect(() => normalizeMcBrowserActionRelativePath('docs/*.zip')).toThrow(
      McBrowserRequestError,
    );
    expect(() =>
      normalizeMcBrowserActionRelativePath('uploads/.af-upload-staging/chunk.bin'),
    ).toThrow(McBrowserRequestError);
    expect(() =>
      normalizeMcBrowserActionRelativePath('uploads/.af-upload-tmp.123/file.bin'),
    ).toThrow(McBrowserRequestError);
    expect(() => normalizeMcBrowserActionRelativePath('C:/Users/admin')).toThrow(
      McBrowserRequestError,
    );

    expect(doMcBrowserActionPathsOverlap('backups/out', 'backups/out')).toBe(true);
    expect(doMcBrowserActionPathsOverlap('backups', 'backups/archive.zip')).toBe(true);
    expect(doMcBrowserActionPathsOverlap('src/app', 'dist/bundle.tar.gz')).toBe(false);
  });

  test('evaluates default-off execute gate and action-specific secondary permissions', () => {
    expect(canExecuteMcBrowserAction('compute_checksums', undefined)).toBe(false);
    expect(
      canExecuteMcBrowserAction('compute_checksums', {
        execute: false,
        read: true,
        create: true,
        download: true,
      }),
    ).toBe(false);

    const execOffEval = evaluateMcBrowserActionPermissions('compute_checksums', {
      execute: false,
      read: true,
    });
    expect(execOffEval.allowed).toBe(false);
    expect(execOffEval.executeEnabled).toBe(false);
    expect(execOffEval.missingPermissions).toContain('execute');

    expect(
      canExecuteMcBrowserAction('compute_checksums', {
        execute: true,
        read: true,
      }),
    ).toBe(true);

    expect(
      canExecuteMcBrowserAction('extract_archive', {
        execute: true,
        read: true,
        create: false,
      }),
    ).toBe(false);
    expect(
      canExecuteMcBrowserAction('extract_archive', {
        execute: true,
        read: true,
        create: true,
      }),
    ).toBe(true);

    expect(
      canExecuteMcBrowserAction('create_archive', {
        execute: true,
        read: true,
        download: false,
        create: true,
      }),
    ).toBe(false);
    expect(
      canExecuteMcBrowserAction('create_archive', {
        execute: true,
        read: true,
        download: true,
        create: true,
      }),
    ).toBe(true);
  });

  test('rejects unknown fields and arbitrary shell fields on action payloads', () => {
    expect(() =>
      validateAndNormalizeMcBrowserActionRequest({
        action: 'compute_checksums',
        path: 'file.bin',
        algorithms: ['sha256'],
        command: 'rm -rf /',
      } as unknown as McBrowserActionRequest),
    ).toThrow(/Arbitrary shell or command execution field/);

    expect(() =>
      validateAndNormalizeMcBrowserActionRequest({
        action: 'inspect_media_metadata',
        path: 'video.mp4',
        extra: true,
      } as unknown as McBrowserActionRequest),
    ).toThrow(/Unknown field/);
  });

  test('dispatches compute_checksums, extract_archive, create_archive, and inspect_media_metadata', async () => {
    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        action: 'compute_checksums',
        success: true,
        path: 'releases/app.bin',
        size: 1024,
        checksums: {
          md5: '1111',
          sha256: '2222',
        },
      }),
    );

    const checksumRes = await computeMcBrowserActionChecksums({
      path: '  releases//app.bin ',
      algorithms: ['sha256', 'md5'],
    });
    expect(checksumRes.checksums.sha256).toBe('2222');
    expect(mockedApiFetch).toHaveBeenLastCalledWith(
      `${MCBROWSER_BASE}/actions`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          action: 'compute_checksums',
          path: 'releases/app.bin',
          algorithms: ['sha256', 'md5'],
        }),
      }),
    );

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse(
        {
          action: 'extract_archive',
          success: true,
          archive_path: 'archives/pkg.tar.zst',
          destination_dir: 'unpacked/pkg',
          format: 'tarzst',
          extracted_files: 5,
          extracted_directories: 2,
          extracted_bytes: 8192,
        },
        201,
      ),
    );

    const extractRes = await extractMcBrowserArchiveAction({
      archive_path: 'archives/pkg.tar.zst',
      destination_dir: 'unpacked/pkg',
    });
    expect(extractRes.format).toBe('tarzst');
    expect(extractRes.extracted_files).toBe(5);

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse(
        {
          action: 'create_archive',
          success: true,
          destination_path: 'bundles/src.tar.lz4',
          format: 'tarlz4',
          entry_count: 12,
          archive_bytes: 4096,
        },
        201,
      ),
    );

    const createRes = await createMcBrowserArchiveAction({
      source_paths: ['src/main.rs', 'src/lib.rs', 'src/main.rs'],
      destination_path: 'bundles/src.tar.lz4',
      format: 'tarlz4',
    });
    expect(createRes.entry_count).toBe(12);
    expect(mockedApiFetch).toHaveBeenLastCalledWith(
      `${MCBROWSER_BASE}/actions`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          action: 'create_archive',
          source_paths: ['src/main.rs', 'src/lib.rs'],
          destination_path: 'bundles/src.tar.lz4',
          format: 'tarlz4',
        }),
      }),
    );

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        action: 'inspect_media_metadata',
        success: true,
        path: 'media/clip.mp4',
        name: 'clip.mp4',
        kind: 'video',
        content_type: 'video/mp4',
        size: 65536,
        modified: '2026-11-02T00:00:00Z',
        resolution: { width: 1920, height: 1080 },
        subtitles: [
          {
            path: 'media/clip.en.vtt',
            name: 'clip.en.vtt',
            label: 'en',
            language: 'en',
            format: 'vtt',
            url: '/api/v1/auth/mcbrowser/media/subtitles?path=media%2Fclip.en.vtt',
          },
        ],
      }),
    );

    const mediaRes = await inspectMcBrowserMediaMetadataAction({
      path: 'media/clip.mp4',
    });
    expect(mediaRes.resolution).toEqual({ width: 1920, height: 1080 });
    expect(mediaRes.subtitles).toHaveLength(1);
  });

  test('validates checksum deduplication and archive overlap before network dispatch', async () => {
    expect(normalizeMcBrowserChecksumAlgorithms(['SHA256', 'md5', 'sha256'])).toEqual([
      'sha256',
      'md5',
    ]);

    await expect(
      dispatchMcBrowserAction({
        action: 'extract_archive',
        archive_path: 'nested/data.zip',
        destination_dir: 'nested/data.zip/out',
      }),
    ).rejects.toThrow(/overlap/);

    await expect(
      dispatchMcBrowserAction({
        action: 'create_archive',
        source_paths: ['project/src'],
        destination_path: 'project/src/out.zip',
        format: 'zip',
      }),
    ).rejects.toThrow(/overlaps/);

    expect(mockedApiFetch).not.toHaveBeenCalled();
  });
});
