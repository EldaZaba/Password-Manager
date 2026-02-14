import React, { ErrorInfo, ReactNode } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

interface RootErrorBoundaryState {
  error: Error | null;
}

class RootErrorBoundary extends React.Component<{ children: ReactNode }, RootErrorBoundaryState> {
  state: RootErrorBoundaryState = {
    error: null,
  };

  static getDerivedStateFromError(error: Error): RootErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Keep console output for diagnostics in Tauri devtools/terminal.
    console.error("Unhandled UI error", error, errorInfo);
  }

  render() {
    if (this.state.error) {
      return (
        <main className="min-h-screen bg-slate-100 p-6 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
          <div className="mx-auto max-w-3xl rounded-xl border border-rose-300 bg-white p-5 dark:border-rose-800 dark:bg-slate-900">
            <h1 className="mb-2 text-xl font-semibold text-rose-700 dark:text-rose-300">Application error</h1>
            <p className="mb-2 text-sm">
              The UI encountered an unexpected runtime error. Restart the app and check the message below.
            </p>
            <pre className="whitespace-pre-wrap rounded bg-slate-100 p-3 text-xs dark:bg-slate-800">
              {this.state.error.message}
            </pre>
          </div>
        </main>
      );
    }

    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <RootErrorBoundary>
      <App />
    </RootErrorBoundary>
  </React.StrictMode>,
);
