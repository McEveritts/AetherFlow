import { TextEncoder, TextDecoder } from 'util';
Object.assign(globalThis, { TextEncoder, TextDecoder });

import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiFetch } from '@/lib/fetcher';
import { MCBROWSER_BASE } from '@/lib/mcbrowser';
import { MCBROWSER_ACTION_ARCHIVE_FORMATS } from '@/lib/mcbrowser-actions';
import { McBrowserActions } from '@/components/mcbrowser/McBrowserActions';

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

describe('McBrowserActions component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('enforces Execute default-off gate when permissions are omitted or execute is false', () => {
    render(<McBrowserActions currentPath="projects" />);

    expect(screen.getByTestId('mcbrowser-actions-execute-badge')).toHaveTextContent(
      'Execute: Off (Default Gate)',
    );
    expect(screen.getByTestId('mcbrowser-actions-execute-gate')).toBeInTheDocument();
    expect(screen.getByTestId('mcbrowser-actions-submit')).toBeDisabled();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  test('enforces secondary permissions per action variant when execute is enabled', () => {
    render(
      <McBrowserActions
        permissions={{
          execute: true,
          read: true,
          create: false,
          download: false,
        }}
      />,
    );

    expect(screen.getByTestId('mcbrowser-actions-submit')).not.toBeDisabled();

    fireEvent.click(screen.getByTestId('mcbrowser-action-tab-extract_archive'));
    expect(screen.getByTestId('mcbrowser-actions-secondary-gate')).toHaveTextContent('create');
    expect(screen.getByTestId('mcbrowser-actions-submit')).toBeDisabled();

    fireEvent.click(screen.getByTestId('mcbrowser-action-tab-create_archive'));
    expect(screen.getByTestId('mcbrowser-actions-secondary-gate')).toHaveTextContent(
      'download, create',
    );
    expect(screen.getByTestId('mcbrowser-actions-submit')).toBeDisabled();
  });

  test('executes compute_checksums with selected algorithms and displays digests', async () => {
    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        action: 'compute_checksums',
        success: true,
        path: 'releases/v1.bin',
        size: 2048,
        checksums: {
          sha256: 'deadbeef256',
          sha512: 'deadbeef512',
        },
      }),
    );

    const onCompleted = jest.fn();

    render(
      <McBrowserActions
        selectedPaths={['releases/v1.bin']}
        permissions={{ execute: true, read: true }}
        onActionCompleted={onCompleted}
      />,
    );

    fireEvent.click(screen.getByLabelText('Algorithm SHA512'));
    fireEvent.click(screen.getByTestId('mcbrowser-actions-submit'));

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-actions-result')).toBeInTheDocument();
    });

    expect(mockedApiFetch).toHaveBeenCalledWith(
      `${MCBROWSER_BASE}/actions`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          action: 'compute_checksums',
          path: 'releases/v1.bin',
          algorithms: ['sha256', 'sha512'],
        }),
      }),
    );
    expect(screen.getByText('deadbeef256')).toBeInTheDocument();
    expect(screen.getByText('deadbeef512')).toBeInTheDocument();
    expect(onCompleted).toHaveBeenCalledTimes(1);
  });

  test('executes extract_archive with explicit source and destination inputs and triggers refresh/navigate', async () => {
    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse(
        {
          action: 'extract_archive',
          success: true,
          archive_path: 'archives/data.tar.zst',
          destination_dir: 'archives/unpacked',
          format: 'tarzst',
          extracted_files: 8,
          extracted_directories: 3,
          extracted_bytes: 16384,
        },
        201,
      ),
    );

    const onRefresh = jest.fn();
    const onNavigate = jest.fn();

    render(
      <McBrowserActions
        initialAction="extract_archive"
        permissions={{ execute: true, read: true, create: true }}
        onRefresh={onRefresh}
        onNavigate={onNavigate}
      />,
    );

    fireEvent.change(screen.getByLabelText(/Source Archive Path/i), {
      target: { value: 'archives/data.tar.zst' },
    });
    fireEvent.change(screen.getByLabelText(/Destination Directory Path/i), {
      target: { value: 'archives/unpacked' },
    });

    fireEvent.click(screen.getByTestId('mcbrowser-actions-submit'));

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-actions-result')).toBeInTheDocument();
    });

    expect(onRefresh).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: /Open Extracted Directory/i }));
    expect(onNavigate).toHaveBeenCalledWith('archives/unpacked');
  });

  test('exposes all 9 archive formats in create_archive and dispatches selected format', async () => {
    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse(
        {
          action: 'create_archive',
          success: true,
          destination_path: 'bundles/pkg.tar.br',
          format: 'tarbr',
          entry_count: 4,
          archive_bytes: 4096,
        },
        201,
      ),
    );

    render(
      <McBrowserActions
        initialAction="create_archive"
        permissions={{ execute: true, read: true, download: true, create: true }}
      />,
    );

    const formatSelect = screen.getByLabelText(/Archive Format/i) as HTMLSelectElement;
    const optionValues = Array.from(formatSelect.options).map((opt) => opt.value);
    expect(optionValues).toEqual([...MCBROWSER_ACTION_ARCHIVE_FORMATS]);

    fireEvent.change(screen.getByLabelText(/Source Paths/i), {
      target: { value: 'src/app.ts\nsrc/utils.ts' },
    });
    fireEvent.change(formatSelect, { target: { value: 'tarbr' } });
    fireEvent.change(screen.getByLabelText(/Destination Archive Path/i), {
      target: { value: 'bundles/pkg.tar.br' },
    });

    fireEvent.click(screen.getByTestId('mcbrowser-actions-submit'));

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-actions-result')).toBeInTheDocument();
    });

    expect(mockedApiFetch).toHaveBeenCalledWith(
      `${MCBROWSER_BASE}/actions`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          action: 'create_archive',
          source_paths: ['src/app.ts', 'src/utils.ts'],
          destination_path: 'bundles/pkg.tar.br',
          format: 'tarbr',
        }),
      }),
    );
  });

  test('executes inspect_media_metadata and renders dimensions and subtitle tracks', async () => {
    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        action: 'inspect_media_metadata',
        success: true,
        path: 'videos/trailer.mp4',
        name: 'trailer.mp4',
        kind: 'video',
        content_type: 'video/mp4',
        size: 1048576,
        modified: '2026-11-02T00:00:00Z',
        resolution: { width: 3840, height: 2160 },
        subtitles: [
          {
            path: 'videos/trailer.en.vtt',
            name: 'trailer.en.vtt',
            label: 'English',
            language: 'en',
            format: 'vtt',
            url: '/api/v1/auth/mcbrowser/media/subtitles?path=videos%2Ftrailer.en.vtt',
          },
        ],
      }),
    );

    render(
      <McBrowserActions
        initialAction="inspect_media_metadata"
        permissions={{ execute: true, read: true }}
      />,
    );

    fireEvent.change(screen.getByLabelText(/Source Media Path/i), {
      target: { value: 'videos/trailer.mp4' },
    });
    fireEvent.click(screen.getByTestId('mcbrowser-actions-submit'));

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-actions-result')).toBeInTheDocument();
    });

    expect(screen.getByText(/3840x2160/)).toBeInTheDocument();
    expect(screen.getByText(/English \(vtt\)/)).toBeInTheDocument();
  });

  test('blocks overlapping paths client-side and handles af:session-expired', async () => {
    render(
      <McBrowserActions
        initialAction="extract_archive"
        permissions={{ execute: true, read: true, create: true }}
      />,
    );

    fireEvent.change(screen.getByLabelText(/Source Archive Path/i), {
      target: { value: 'backups/archive.zip' },
    });
    fireEvent.change(screen.getByLabelText(/Destination Directory Path/i), {
      target: { value: 'backups/archive.zip' },
    });

    fireEvent.click(screen.getByTestId('mcbrowser-actions-submit'));

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-actions-error')).toHaveTextContent(/overlap/i);
    });
    expect(mockedApiFetch).not.toHaveBeenCalled();

    act(() => {
      window.dispatchEvent(new Event('af:session-expired'));
    });

    expect(screen.getByTestId('mcbrowser-actions-error')).toHaveTextContent(
      /session has expired/i,
    );
    expect(screen.getByTestId('mcbrowser-actions-submit')).toBeDisabled();
  });
});
