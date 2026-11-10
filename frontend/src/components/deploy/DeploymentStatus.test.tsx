import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { DeploymentStatus } from './DeploymentStatus';
import { useDeploymentStream } from '../../hooks/useDeploymentStream';

jest.mock('../../hooks/useDeploymentStream');

const mockUseDeploymentStream = useDeploymentStream as jest.MockedFunction<typeof useDeploymentStream>;

describe('DeploymentStatus UI Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders null when not triggered', () => {
    mockUseDeploymentStream.mockReturnValue({
      logs: [],
      isDeploying: false,
      status: 'idle',
      error: null,
    });

    const { container } = render(<DeploymentStatus appName="jellyfin" isTriggered={false} />);
    expect(container.firstChild).toBeNull();
  });

  it('embeds deployment output using open-canvas section without floating glass-card surface', () => {
    mockUseDeploymentStream.mockReturnValue({
      logs: ['[STEP 1/3] Preparing container...', '[STEP 2/3] Allocating port...'],
      isDeploying: true,
      status: 'deploying',
      error: null,
    });

    render(<DeploymentStatus appName="jellyfin" isTriggered={true} />);

    const card = screen.getByTestId('deployment-status-card');
    expect(card).toBeInTheDocument();
    expect(card).toHaveClass('obs-canvas-section', 'min-w-0', 'max-w-full');
    expect(card).not.toHaveClass('glass-card', 'glass-panel', 'glass-hero');

    expect(screen.getByText('Deployment Orchestrator')).toBeInTheDocument();
    expect(screen.getByText('[STEP 1/3] Preparing container...')).toBeInTheDocument();
    expect(screen.getByText('[STEP 2/3] Allocating port...')).toBeInTheDocument();
  });

  it('highlights success, rollback, and error steps with appropriate status accents', () => {
    mockUseDeploymentStream.mockReturnValue({
      logs: [
        '[STEP 1] Validating manifest',
        '[ERROR] Port binding conflict on 8096',
        '[ROLLBACK] Restoring previous configuration',
        '[SUCCESS] Reverted to safe baseline',
      ],
      isDeploying: false,
      status: 'success',
      error: null,
    });

    render(<DeploymentStatus appName="jellyfin" isTriggered={true} />);

    const stepLog = screen.getByText('[STEP 1] Validating manifest');
    expect(stepLog).toHaveClass('text-blue-400');

    const errorLog = screen.getByText('[ERROR] Port binding conflict on 8096');
    expect(errorLog).toHaveClass('text-red-400');

    const rollbackLog = screen.getByText('[ROLLBACK] Restoring previous configuration');
    expect(rollbackLog).toHaveClass('text-orange-400');

    const successLog = screen.getByText('[SUCCESS] Reverted to safe baseline');
    expect(successLog).toHaveClass('text-emerald-400');
  });

  it('displays deployment stream error messages', () => {
    mockUseDeploymentStream.mockReturnValue({
      logs: ['[STEP 1] Connecting to deployment socket...'],
      isDeploying: false,
      status: 'error',
      error: new Error('WebSocket connection timed out'),
    });

    render(<DeploymentStatus appName="jellyfin" isTriggered={true} />);

    expect(screen.getByText('WebSocket connection timed out')).toBeInTheDocument();
  });
});
