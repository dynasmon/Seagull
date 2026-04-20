import { Component, type ErrorInfo, type ReactNode } from "react";
import { Link } from "react-router-dom";

import { attemptRouteLoadRecovery, isRecoverableRouteLoadError } from "@/app/route_error_recovery";

type Props = {
  currentPath: string;
  children: ReactNode;
};

type State = {
  error: Error | null;
  recovering: boolean;
};

export default class RouteErrorBoundary extends Component<Props, State> {
  state: State = {
    error: null,
    recovering: false,
  };

  static getDerivedStateFromError(error: Error): State {
    return {
      error,
      recovering: false,
    };
  }

  componentDidCatch(error: Error, _errorInfo: ErrorInfo): void {
    if (!isRecoverableRouteLoadError(error)) return;
    const recovering = attemptRouteLoadRecovery(this.props.currentPath);
    if (recovering) {
      this.setState({ recovering: true });
    }
  }

  render() {
    if (!this.state.error) {
      return this.props.children;
    }

    const title = this.state.recovering
      ? "Recovering Route"
      : "Page Load Failed";
    const description = this.state.recovering
      ? "The portal is reloading to recover a stale route bundle."
      : "This page failed to load. Reload the portal or return to Overview.";

    return (
      <div className="min-h-[55vh] rounded-xl border border-border/60 bg-background/70 p-6 backdrop-blur-md">
        <div className="mx-auto flex max-w-xl flex-col gap-4">
          <div>
            <h2 className="text-lg font-semibold">{title}</h2>
            <p className="mt-2 text-sm text-muted-foreground">{description}</p>
          </div>

          {!this.state.recovering ? (
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => window.location.reload()}
                className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-95"
              >
                Reload portal
              </button>
              <Link
                to="/overview"
                className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm hover:bg-muted/30"
              >
                Go to Overview
              </Link>
            </div>
          ) : null}
        </div>
      </div>
    );
  }
}
