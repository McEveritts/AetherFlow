'use client';

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

interface Props {
  children?: ReactNode;
  fallback?: ReactNode;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in tab:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="flex items-center justify-center h-full min-h-[50vh]">
          <div className="glass-card p-8 flex flex-col items-center gap-4 text-center max-w-lg border-red-500/20 bg-red-950/20">
            <div className="w-16 h-16 rounded-full bg-red-500/20 flex items-center justify-center text-red-400 mb-2">
              <AlertOctagon className="w-8 h-8" />
            </div>
            <h2 className="text-xl font-bold text-slate-100">Component Crashed</h2>
            <p className="text-sm text-slate-400">
              An unexpected error occurred while rendering this interface. The rest of the dashboard remains operational.
            </p>
            {this.state.error && (
              <div className="w-full mt-4 text-left bg-slate-950/50 p-4 rounded-lg border border-red-500/10 overflow-x-auto">
                <code className="text-xs text-red-300 font-mono break-all">
                  {this.state.error.message}
                </code>
              </div>
            )}
            <button
              onClick={this.handleReset}
              className="mt-6 glass-button-primary px-6 py-2 flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Retry Rendering</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
