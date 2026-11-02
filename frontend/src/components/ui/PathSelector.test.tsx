import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import PathSelector from './PathSelector';
import { apiFetch } from '@/lib/fetcher';

jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));

const mockedFetch = jest.mocked(apiFetch);

describe('host filesystem path picker authorization', () => {
  beforeEach(() => jest.clearAllMocks());

  it('explains forbidden host browsing without suggesting alternate host roots', async () => {
    mockedFetch.mockResolvedValue({ ok: false, status: 403 } as Response);
    render(<PathSelector value="/tmp" onChange={jest.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Browse Directories' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Host directory browsing requires an active administrator. Use McBrowser for your files.'
    );
    expect(screen.queryByText('No subdirectories found in this path')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '/home' })).not.toBeInTheDocument();
  });

  it('preserves authorized administrator directory selection', async () => {
    mockedFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ directories: ['library'] }),
    } as Response);
    const onChange = jest.fn();
    render(<PathSelector value="/mnt" onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: 'Browse Directories' }));
    fireEvent.click(await screen.findByRole('button', { name: 'library' }));
    expect(onChange).toHaveBeenCalledWith('/mnt/library');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
