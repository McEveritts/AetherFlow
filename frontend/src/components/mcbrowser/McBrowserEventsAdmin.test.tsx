import { TextEncoder, TextDecoder } from 'util';
Object.assign(globalThis, { TextEncoder, TextDecoder });

import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiFetch } from '@/lib/fetcher';
import { MCBROWSER_BASE } from '@/lib/mcbrowser';
import { McBrowserEventsAdmin } from '@/components/mcbrowser/McBrowserEventsAdmin';

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

const SAMPLE_EVENT_ID = '123e4567-e89b-12d3-a456-426614174000';

function setupInitialLoadMocks(queueEnabled = true) {
  mockedApiFetch
    .mockResolvedValueOnce(
      mockJsonResponse({
        events: [
          {
            event_id: SAMPLE_EVENT_ID,
            timestamp: '2026-11-02T00:00:00Z',
            user_id: 7,
            username: 'alice',
            trigger: 'upload_completed',
            relative_path: 'uploads/report.pdf',
            destination_path: null,
            byte_delta: 4096,
            status: 'pending',
            error_code: null,
            updated_at: '2026-11-02T00:00:00Z',
          },
        ],
        truncated: false,
      }),
    )
    .mockResolvedValueOnce(
      mockJsonResponse({
        enabled: queueEnabled,
        queue_enabled: queueEnabled,
      }),
    )
    .mockResolvedValueOnce(
      mockJsonResponse({
        enabled: queueEnabled,
        queue_enabled: queueEnabled,
        tasks: [
          {
            queue_id: 1,
            event_id: SAMPLE_EVENT_ID,
            status: 'queued',
            event: {
              event_id: SAMPLE_EVENT_ID,
              timestamp: '2026-11-02T00:00:00Z',
              user_id: 7,
              username: 'alice',
              trigger: 'upload_completed',
              relative_path: 'uploads/report.pdf',
              destination_path: null,
              byte_delta: 4096,
            },
            enqueued_at: '2026-11-02T00:00:01Z',
            acknowledged_at: null,
          },
        ],
        truncated: false,
      }),
    );
}

describe('McBrowserEventsAdmin component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('loads initial audit events, settings, and task queue on mount', async () => {
    setupInitialLoadMocks(true);

    render(<McBrowserEventsAdmin />);

    await waitFor(() => {
      expect(screen.getByTestId(`mcbrowser-audit-row-${SAMPLE_EVENT_ID}`)).toBeInTheDocument();
    });

    expect(screen.getByTestId('mcbrowser-events-queue-state')).toHaveTextContent(
      'Queue Enabled',
    );
    expect(screen.getByText('uploads/report.pdf')).toBeInTheDocument();
  });

  test('toggles event queue settings via PUT /events/settings', async () => {
    setupInitialLoadMocks(true);

    const onSettingsChange = jest.fn();
    render(<McBrowserEventsAdmin onSettingsChange={onSettingsChange} />);

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-events-queue-toggle')).not.toBeDisabled();
    });

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        enabled: false,
        queue_enabled: false,
      }),
    );

    fireEvent.click(screen.getByTestId('mcbrowser-events-queue-toggle'));

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-events-queue-state')).toHaveTextContent(
        'Queue Disabled',
      );
    });

    expect(mockedApiFetch).toHaveBeenLastCalledWith(
      `${MCBROWSER_BASE}/events/settings`,
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ enabled: false, queue_enabled: false }),
      }),
    );
    expect(onSettingsChange).toHaveBeenCalledWith({
      enabled: false,
      queue_enabled: false,
    });
  });

  test('applies bounded audit filters and rejects out-of-range limits client-side', async () => {
    setupInitialLoadMocks(true);

    render(<McBrowserEventsAdmin />);

    await waitFor(() => {
      expect(screen.getByTestId(`mcbrowser-audit-row-${SAMPLE_EVENT_ID}`)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/Audit Status/i), {
      target: { value: 'completed' },
    });
    fireEvent.change(screen.getByLabelText(/Event Trigger/i), {
      target: { value: 'share_created' },
    });
    fireEvent.change(screen.getByLabelText(/User ID/i), {
      target: { value: '12' },
    });
    fireEvent.change(screen.getByLabelText(/Bounded Limit/i), {
      target: { value: '50' },
    });

    setupInitialLoadMocks(true);
    fireEvent.click(screen.getByTestId('mcbrowser-audit-apply-filters'));

    await waitFor(() => {
      expect(mockedApiFetch).toHaveBeenCalledWith(
        `${MCBROWSER_BASE}/events?limit=50&status=completed&trigger=share_created&user_id=12`,
        expect.objectContaining({ method: 'GET' }),
      );
    });

    fireEvent.change(screen.getByLabelText(/Bounded Limit/i), {
      target: { value: '999' },
    });
    fireEvent.click(screen.getByTestId('mcbrowser-audit-apply-filters'));

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-events-error')).toHaveTextContent(
        /between 1 and 500/i,
      );
    });
  });

  test('acknowledges queued task via POST /events/queue/:event_id/ack and updates row status', async () => {
    setupInitialLoadMocks(true);
    const onTaskAcknowledged = jest.fn();

    render(
      <McBrowserEventsAdmin
        initialTab="queue"
        onTaskAcknowledged={onTaskAcknowledged}
      />,
    );

    await waitFor(() => {
      expect(screen.getByTestId(`mcbrowser-queue-row-${SAMPLE_EVENT_ID}`)).toBeInTheDocument();
    });

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        success: true,
        task: {
          queue_id: 1,
          event_id: SAMPLE_EVENT_ID,
          status: 'acknowledged',
          event: {
            event_id: SAMPLE_EVENT_ID,
            timestamp: '2026-11-02T00:00:00Z',
            user_id: 7,
            username: 'alice',
            trigger: 'upload_completed',
            relative_path: 'uploads/report.pdf',
            destination_path: null,
            byte_delta: 4096,
          },
          enqueued_at: '2026-11-02T00:00:01Z',
          acknowledged_at: '2026-11-02T00:05:00Z',
        },
      }),
    );

    const ackButton = screen.getByTestId(`mcbrowser-queue-ack-${SAMPLE_EVENT_ID}`);
    fireEvent.click(ackButton);

    await waitFor(() => {
      expect(ackButton).toHaveTextContent('Acknowledged');
      expect(ackButton).toBeDisabled();
    });

    expect(mockedApiFetch).toHaveBeenLastCalledWith(
      `${MCBROWSER_BASE}/events/queue/${SAMPLE_EVENT_ID}/ack`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({}),
      }),
    );
    expect(onTaskAcknowledged).toHaveBeenCalledTimes(1);
  });

  test('handles af:session-expired by disabling controls and showing alert', async () => {
    setupInitialLoadMocks(true);

    render(<McBrowserEventsAdmin />);

    await waitFor(() => {
      expect(screen.getByTestId('mcbrowser-events-queue-toggle')).not.toBeDisabled();
    });

    act(() => {
      window.dispatchEvent(new Event('af:session-expired'));
    });

    expect(screen.getByTestId('mcbrowser-events-error')).toHaveTextContent(
      /session has expired/i,
    );
    expect(screen.getByTestId('mcbrowser-events-queue-toggle')).toBeDisabled();
  });
});
