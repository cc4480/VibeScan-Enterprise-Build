import { Switch, Route, Router as WouterRouter, useLocation, Link } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, Component, type ReactNode } from "react";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import { useGetCurrentAuthUser } from "@workspace/api-client-react";

import { Layout } from "@/components/layout";
import LandingPage from "@/pages/landing";
import DashboardPage from "@/pages/dashboard";
import ScanFormPage from "@/pages/scan-form";
import ScanProgressPage from "@/pages/scan-progress";
import ReportViewer from "@/pages/report-viewer";
import MonitorPage from "@/pages/monitor";
import SharedReport from "@/pages/shared-report";
import LearnPage from "@/pages/learn";
import SettingsPage from "@/pages/settings";
import DomainsPage from "@/pages/domains";
import LegalPage from "@/pages/legal";
import BotPage from "@/pages/bot";
import SignInPage from "@/pages/sign-in";
import RegisterPage from "@/pages/register";
import ForgotPasswordPage from "@/pages/forgot-password";
import ResetPasswordPage from "@/pages/reset-password";
import VerifyEmailPage from "@/pages/verify-email";

// ── ErrorBoundary ────────────────────────────────────────────────────────────

interface ErrorBoundaryState { hasError: boolean; message: string }

class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, message: "" };
  }

  static getDerivedStateFromError(error: unknown): ErrorBoundaryState {
    return {
      hasError: true,
      message: error instanceof Error ? error.message : "An unexpected error occurred.",
    };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center px-4">
          <div className="text-center max-w-md">
            <h1 className="text-2xl font-bold mb-2">Something went wrong</h1>
            <p className="text-muted-foreground text-sm mb-6">{this.state.message}</p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium"
            >
              Reload page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// ── ProtectedRoute ───────────────────────────────────────────────────────────

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { data, isLoading, isFetching, isError, refetch } = useGetCurrentAuthUser();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  // GET /auth/user is documented to always answer 200, with `user: null` as
  // the normal, successful shape of "not signed in" (see openapi.yaml's
  // AuthUserEnvelope — user is `AuthUser | null`, no 401 is ever declared for
  // this route). That is NOT the same situation as the request actually
  // failing, and showing one identical alarming screen for both — as this
  // used to — meant every ordinary "you aren't signed in on this
  // browser/device" case (an expired or cleared session, a bookmark to a
  // protected page, mobile browsers clearing storage more aggressively than
  // desktop) read as "Can't reach the server... this is usually temporary,"
  // with a "Try again" button that cannot do anything for that case: retrying
  // an unauthenticated request just returns the same no-user response.
  if (isError) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="text-center max-w-md">
          <h1 className="text-2xl font-bold mb-2">Can’t reach the server</h1>
          <p className="text-muted-foreground text-sm mb-6">
            We couldn’t confirm your session. This is usually temporary.
          </p>
          <button
            onClick={() => void refetch()}
            disabled={isFetching}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium disabled:opacity-60"
          >
            {isFetching ? "Retrying…" : "Try again"}
          </button>
          <p className="mt-6 text-xs text-muted-foreground">
            <Link href="/sign-in" className="underline underline-offset-4">
              Sign in instead
            </Link>
          </p>
        </div>
      </div>
    );
  }

  if (!data?.user) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="text-center max-w-md">
          <h1 className="text-2xl font-bold mb-2">Sign in to continue</h1>
          <p className="text-muted-foreground text-sm mb-6">
            This page needs an active session. Sign in to pick up where you left off.
          </p>
          <Link
            href="/sign-in"
            className="inline-block px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium"
          >
            Sign in
          </Link>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}

// ── Query client ─────────────────────────────────────────────────────────────

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // retry once: a single transient failure (dropped connection, dev-server
      // restart) previously flipped a query straight to its error state, which
      // blanked whatever it was rendering until the next refetch.
      retry: 1,
      // staleTime 0 combined with the refetch flags below re-fetched every
      // query on every window focus and every mount, so simply alt-tabbing back
      // re-ran the whole screen's data. 30s keeps data fresh without the storm.
      staleTime: 30_000,
      refetchOnWindowFocus: true,
      refetchOnMount: true,
    },
  },
});

function ScrollToTop() {
  const [location] = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location]);
  return null;
}

function Router() {
  return (
    <>
    <ScrollToTop />
    <Switch>
      {/* Public share page — rendered without the app Layout (no nav/auth required) */}
      <Route path="/share/:token" component={SharedReport} />

      {/* Account screens sit outside ProtectedRoute deliberately: a reset or
          confirmation link arrives by email and has to work whatever the
          session state is, including none at all. */}
      <Route path="/sign-in" component={SignInPage} />
      <Route path="/register" component={RegisterPage} />
      <Route path="/forgot-password" component={ForgotPasswordPage} />
      <Route path="/reset-password" component={ResetPasswordPage} />
      <Route path="/verify-email" component={VerifyEmailPage} />

      {/* All other routes wrapped in the authenticated Layout */}
      <Route>
        <ProtectedRoute>
        <Layout>
          <Switch>
            <Route path="/" component={LandingPage} />
            <Route path="/dashboard" component={DashboardPage} />
            <Route path="/scan" component={ScanFormPage} />
            <Route path="/scan/:id" component={ScanProgressPage} />
            <Route path="/report/:id" component={ReportViewer} />
            <Route path="/monitor" component={MonitorPage} />
            <Route path="/learn" component={LearnPage} />
            {/* Documentation the scanner's User-Agent points at, for site owners
                who find the bot in their logs. Public, like the legal pages. */}
            <Route path="/bot" component={BotPage} />
            <Route path="/privacy">{() => <LegalPage kind="privacy" />}</Route>
            <Route path="/terms">{() => <LegalPage kind="terms" />}</Route>
            <Route path="/settings" component={SettingsPage} />
            <Route path="/domains" component={DomainsPage} />
            <Route component={NotFound} />
          </Switch>
        </Layout>
        </ProtectedRoute>
      </Route>
    </Switch>
    </>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
            <Router />
          </WouterRouter>
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
