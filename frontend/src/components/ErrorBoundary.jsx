import { Component } from 'react';
import { AlertTriangle, Home, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';

export default class ErrorBoundary extends Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error('ErrorBoundary caught an error:', error, errorInfo);
        this.setState({ errorInfo });
    }

    render() {
        if (this.state.hasError) {
            return (
                <div className="flex h-[80vh] flex-col items-center justify-center p-6 text-center animate-fade-in">
                    <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-red-500/10 text-red-500">
                        <AlertTriangle className="h-8 w-8" />
                    </div>
                    <h1 className="mb-2 text-xl font-bold text-text-primary">Something went wrong</h1>
                    <p className="mb-8 max-w-md text-sm text-text-muted">
                        The application encountered an unexpected rendering error.
                    </p>

                    <div className="mb-8 flex flex-col gap-3 sm:flex-row">
                        <button
                            onClick={() => {
                                this.setState({ hasError: false, error: null, errorInfo: null });
                                window.history.back();
                            }}
                            className="flex items-center justify-center gap-2 rounded-lg bg-white/5 border border-white/10 px-5 py-2.5 text-sm font-medium text-text-primary transition-colors hover:bg-white/10"
                            style={{ background: 'var(--bg-surface-raised)', borderColor: 'var(--border-subtle)' }}
                        >
                            <RefreshCw className="h-4 w-4" /> Go Back
                        </button>
                        <Link
                            to="/"
                            onClick={() => this.setState({ hasError: false, error: null, errorInfo: null })}
                            className="flex items-center justify-center gap-2 rounded-lg border border-transparent px-5 py-2.5 text-sm font-medium text-white transition-colors"
                            style={{ background: 'var(--color-accent)' }}
                        >
                            <Home className="h-4 w-4" /> Return to Home
                        </Link>
                    </div>

                    {(this.state.error || this.state.errorInfo) && (
                        <div className="w-full max-w-2xl overflow-hidden rounded-lg border border-border-subtle bg-[#050505]" style={{ background: 'var(--bg-surface)' }}>
                            <div className="border-b border-border-subtle bg-red-500/5 px-4 py-2 text-left text-xs font-semibold text-red-400">
                                Error Details
                            </div>
                            <div className="p-4 overflow-auto max-h-64 text-left">
                                {this.state.error && (
                                    <div className="mb-3 font-mono text-xs text-red-300">
                                        {this.state.error.toString()}
                                    </div>
                                )}
                                {this.state.errorInfo && (
                                    <pre className="font-mono text-[10px] text-text-muted whitespace-pre-wrap">
                                        {this.state.errorInfo.componentStack}
                                    </pre>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        return this.props.children;
    }
}
