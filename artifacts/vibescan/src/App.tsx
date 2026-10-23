import { Switch, Route, Router as WouterRouter, useLocation, Link } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, Component, Suspense, type ReactNode } from "react";
import { lazyPage } from "@/lib/lazy-page";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import { useGetCurrentAuthUser } from "@workspace/api-client-react";

import { Layout } from "@/components/layout";
import LandingPage from "@/pages/landing";
import LearnPage from "@/pages/learn";
import LearnCheckPage from "@/pages/learn-check";
import FeedbackPage from "@/pages/feedback";
import LegalPage from "@/pages/legal";
import BotPage from "@/pages/bot";
import AboutPage from "@/pages/about";
import SignInPage from "@/pages/sign-in";

// Signed-in pages load when first opened (lib/lazy-page.ts); the public pages above stay in the main file.
const DashboardPage = lazyPage(() => import("@/pages/dashboard"));
const ScanFormPage = lazyPage(() => import("@/pages/scan-form"));
const ScanProgressPage = lazyPage(() => import("@/pages/scan-progress"));
const OAuthAuthorizePage = lazyPage(() => import("@/pages/oauth-authorize"));
const ReportViewer = lazyPage(() => import("@/pages/report-viewer"));
const MonitorPage = lazyPage(() => import("@/pages/monitor"));
const SharedReport = lazyPage(() => import("@/pages/shared-report"));
const TrustPage = lazyPage(() => import("@/pages/trust-page"));
const TeamAcceptPage = lazyPage(() => import("@/pages/team-accept"));
const TeamSharedPage = lazyPage(() => import("@/pages/team-shared"));
const SettingsPage = lazyPage(() => import("@/pages/settings"));
const DomainsPage = lazyPage(() => import("@/pages/domains"));
const RegisterPage = lazyPage(() => import("@/pages/register"));
const ForgotPasswordPage = lazyPage(() => import("@/pages/forgot-password"));
const ResetPasswordPage = lazyPage(() => import("@/pages/reset-password"));
const VerifyEmailPage = lazyPage(() => import("@/pages/verify-email"));

/** Shown for the moment a page's file is on its way. */
function PageLoading() {
  return (
    <div role="status" aria-label="Loading" className="flex items-center justify-center min-h-[40vh]">
      <div className="w-8 h-8 rounded-full border-2 border-primary/30 border-t-primary animate-spin" />
    </div>
  );
}

// ── ErrorBoundary ────────────────────────────────────────────────────────────

interface ErrorBoundaryState { hasError: boolean; message: string }

/**
 * `page` is the per-route boundary: it sits inside the layout, so one crashed page shows a retry and a way home
 * while the navigation stays. Without it, this is the app-wide last resort.
 */
class ErrorBoundary extends Component<{ children: ReactNode; page?: boolean }, ErrorBoundaryState> {
  constructor(props: { children: ReactNode; page?: boolean }) {
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
    if (this.state.hasError && this.props.page) {
      return (
        <div role="alert" className="flex flex-col items-center justify-center text-center min-h-[40vh] px-4 py-10">
          <h1 className="text-xl font-bold mb-2">This page could not be shown</h1>
          <p className="text-muted-foreground text-sm mb-6">{this.state.message}</p>
          <div className="flex gap-3">
            <button
              onClick={() => this.setState({ hasError: false, message: "" })}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium"
            >
              Try again
            </button>
            <Link href="/" className="px-4 py-2 border border-white/10 rounded-lg text-sm font-medium hover:bg-white/5">
              Go to home
            </Link>
          </div>
        </div>
      );
    }
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
  const [location] = useLocation();
  return (
    <>
    <ScrollToTop />
    <Suspense fallback={<PageLoading />}>
    <Switch>
      {/* Public share page — rendered without the app Layout (no nav/auth required) */}
      <Route path="/share/:token" component={SharedReport} />
      {/* Public trust page for a verified domain — also without the app Layout */}
      <Route path="/trust/:domain" component={TrustPage} />

      {/* Account screens sit outside ProtectedRoute deliberately: a reset or
          confirmation link arrives by email and has to work whatever the
          session state is, including none at all. */}
      <Route path="/sign-in" component={SignInPage} />
      {/* The consent screen an AI editor sends people to. It checks the session itself and sends
          anyone signed out to /sign-in and back, so it sits outside ProtectedRoute. */}
      <Route path="/oauth/authorize" component={OAuthAuthorizePage} />
      <Route path="/register" component={RegisterPage} />
      <Route path="/forgot-password" component={ForgotPasswordPage} />
      <Route path="/reset-password" component={ResetPasswordPage} />
      <Route path="/verify-email" component={VerifyEmailPage} />
      {/* An invitation link has to work whatever the session state is; the page itself asks for sign-in. */}
      <Route path="/team/accept" component={TeamAcceptPage} />

      {/* Every route shares the Layout chrome, which renders a "Sign in" link
          when there is no session. Signing in is mandatory for the app itself,
          but these five pages have to stay reachable by someone who does not
          have an account yet, so the gate is applied per route rather than to
          the whole Layout:

            /privacy, /terms — linked from the registration form. Putting the
              terms you are asked to accept behind the account you cannot make
              without accepting them is a circle.
            /bot — the address the scanner's own User-Agent gives every host it
              probes (lib/browser.ts). A site owner who finds the traffic in
              their logs and comes looking must not meet a login wall.
            /, /learn — the marketing pages. Gating the pitch at the audience it
              was written for made the whole site invisible to new visitors. */}
      <Route>
        <Layout>
          {/* Inside the layout, so the navigation stays put while a page's file loads. The boundary is keyed by
              the location, so moving to another page clears a crash. */}
          <ErrorBoundary page key={location}>
          <Suspense fallback={<PageLoading />}>
          <Switch>
            <Route path="/" component={LandingPage} />
            <Route path="/learn" component={LearnPage} />
            <Route path="/learn/:id" component={LearnCheckPage} />
            <Route path="/bot" component={BotPage} />
            <Route path="/about" component={AboutPage} />
            <Route path="/privacy">{() => <LegalPage kind="privacy" />}</Route>
            <Route path="/terms">{() => <LegalPage kind="terms" />}</Route>
            <Route path="/feedback" component={FeedbackPage} />

            <Route path="/dashboard">{() => <ProtectedRoute><DashboardPage /></ProtectedRoute>}</Route>
            <Route path="/scan">{() => <ProtectedRoute><ScanFormPage /></ProtectedRoute>}</Route>
            <Route path="/scan/:id">{() => <ProtectedRoute><ScanProgressPage /></ProtectedRoute>}</Route>
            <Route path="/report/:id">{() => <ProtectedRoute><ReportViewer /></ProtectedRoute>}</Route>
            <Route path="/monitor">{() => <ProtectedRoute><MonitorPage /></ProtectedRoute>}</Route>
            <Route path="/team/shared/:id">{() => <ProtectedRoute><TeamSharedPage /></ProtectedRoute>}</Route>
            <Route path="/settings">{() => <ProtectedRoute><SettingsPage /></ProtectedRoute>}</Route>
            <Route path="/domains">{() => <ProtectedRoute><DomainsPage /></ProtectedRoute>}</Route>
            <Route component={NotFound} />
          </Switch>
          </Suspense>
          </ErrorBoundary>
        </Layout>
      </Route>
    </Switch>
    </Suspense>
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
