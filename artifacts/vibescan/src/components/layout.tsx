import { Link, useLocation } from "wouter";
import { Shield, LayoutDashboard, Menu, X, Plus, BookOpen, Bell, Settings, LogOut, ShieldCheck} from "lucide-react";
import { useState, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useGetCurrentAuthUser } from "@workspace/api-client-react";
import { cn } from "@/lib/utils";
import { signOut } from "@/lib/account-api";

/**
 * Sign-in control.
 *
 * Accounts are additive here, not a gate: an anonymous visitor is still a real
 * user with real scans, so this offers to preserve that history rather than
 * demanding a login. A signed-in account is the one with an email — anonymous
 * identities have none.
 */
function AccountNav() {
  const { data } = useGetCurrentAuthUser();
  const queryClient = useQueryClient();
  const [signingOut, setSigningOut] = useState(false);
  const email = data?.user?.email ?? null;

  if (!email) {
    return (
      <Link
        href="/sign-in"
        className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
      >
        Sign in
      </Link>
    );
  }

  async function handleSignOut() {
    setSigningOut(true);
    try {
      await signOut();
    } finally {
      // Refetch regardless: on success the identity changed, and on failure the
      // displayed state should still be re-read from the server rather than
      // guessed at.
      await queryClient.invalidateQueries();
      setSigningOut(false);
    }
  }

  return (
    <div className="flex items-center gap-3">
      <span className="text-sm text-muted-foreground max-w-[14rem] truncate" title={email}>
        {email}
      </span>
      <button
        type="button"
        onClick={handleSignOut}
        disabled={signingOut}
        className="flex items-center gap-1.5 text-sm font-medium text-muted-foreground hover:text-foreground disabled:opacity-60 transition-colors"
      >
        <LogOut className="w-3.5 h-3.5" />
        {signingOut ? "Signing out…" : "Sign out"}
      </button>
    </div>
  );
}

export function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden">
      {/* Background ambient glow */}
      <div className="fixed inset-0 pointer-events-none z-[-1] overflow-hidden">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-primary/5 blur-[120px]" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[30%] h-[30%] rounded-full bg-blue-500/5 blur-[100px]" />
      </div>

      <header
        className={cn(
          "fixed top-0 left-0 right-0 z-50 transition-all duration-300 border-b",
          scrolled
            ? "bg-background/80 backdrop-blur-lg border-white/5 shadow-lg shadow-black/20 py-3"
            : "bg-transparent border-transparent py-5",
        )}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-emerald-700 flex items-center justify-center shadow-lg shadow-primary/20 group-hover:shadow-primary/40 transition-all">
              <Shield className="w-5 h-5 text-primary-foreground" />
            </div>
            <span className="font-display font-bold text-xl tracking-tight text-foreground">
              SecScan
            </span>
          </Link>

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center gap-8">
            <Link
              href="/"
              className={cn(
                "text-sm font-medium transition-colors hover:text-foreground",
                location === "/" ? "text-foreground" : "text-muted-foreground",
              )}
            >
              Home
            </Link>
            <Link
              href="/dashboard"
              className={cn(
                "text-sm font-medium transition-colors hover:text-foreground flex items-center gap-1.5",
                location === "/dashboard" ? "text-foreground" : "text-muted-foreground",
              )}
            >
              <LayoutDashboard className="w-3.5 h-3.5" /> Dashboard
            </Link>
            <Link
              href="/monitor"
              className={cn(
                "text-sm font-medium transition-colors hover:text-foreground flex items-center gap-1.5",
                location === "/monitor" ? "text-foreground" : "text-muted-foreground",
              )}
            >
              <Bell className="w-3.5 h-3.5" /> Monitor
            </Link>
            <Link
              href="/learn"
              className={cn(
                "text-sm font-medium transition-colors hover:text-foreground flex items-center gap-1.5",
                location === "/learn" ? "text-foreground" : "text-muted-foreground",
              )}
            >
              <BookOpen className="w-3.5 h-3.5" /> Learn
            </Link>
            <Link
              href="/domains"
              className={cn(
                "text-sm font-medium transition-colors hover:text-foreground flex items-center gap-1.5",
                location === "/domains" ? "text-foreground" : "text-muted-foreground",
              )}
            >
              <ShieldCheck className="w-3.5 h-3.5" /> Domains
            </Link>
            <Link
              href="/settings"
              className={cn(
                "text-sm font-medium transition-colors hover:text-foreground flex items-center gap-1.5",
                location === "/settings" ? "text-foreground" : "text-muted-foreground",
              )}
            >
              <Settings className="w-3.5 h-3.5" /> Settings
            </Link>

            <div className="w-px h-6 bg-border" />

            <AccountNav />

            <Link
              href="/scan"
              className="flex items-center gap-1.5 px-5 py-2.5 bg-primary text-primary-foreground text-sm font-semibold rounded-lg shadow-[0_0_15px_rgba(20,184,120,0.3)] hover:shadow-[0_0_25px_rgba(20,184,120,0.5)] hover:-translate-y-0.5 transition-all duration-200"
            >
              <Plus className="w-4 h-4" /> New Scan
            </Link>
          </nav>

          {/* Mobile toggle */}
          <button
            className="md:hidden p-2 text-foreground"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="md:hidden absolute top-full left-0 right-0 bg-background/95 backdrop-blur-xl border-b border-white/5 py-4 px-4 flex flex-col gap-3 shadow-2xl">
            <Link
              href="/"
              onClick={() => setMobileMenuOpen(false)}
              className="px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary"
            >
              Home
            </Link>
            <Link
              href="/dashboard"
              onClick={() => setMobileMenuOpen(false)}
              className="px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary flex items-center gap-2"
            >
              <LayoutDashboard className="w-4 h-4" /> Dashboard
            </Link>
            <Link
              href="/monitor"
              onClick={() => setMobileMenuOpen(false)}
              className="px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary flex items-center gap-2"
            >
              <Bell className="w-4 h-4" /> Monitor
            </Link>
            <Link
              href="/learn"
              onClick={() => setMobileMenuOpen(false)}
              className="px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary flex items-center gap-2"
            >
              <BookOpen className="w-4 h-4" /> Learn
            </Link>
            <Link
              href="/domains"
              onClick={() => setMobileMenuOpen(false)}
              className="px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary flex items-center gap-2"
            >
              <ShieldCheck className="w-4 h-4" /> Domains
            </Link>
            <Link
              href="/settings"
              onClick={() => setMobileMenuOpen(false)}
              className="px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary flex items-center gap-2"
            >
              <Settings className="w-4 h-4" /> Settings
            </Link>
            <div className="h-px bg-border mx-4" />
            <Link
              href="/scan"
              onClick={() => setMobileMenuOpen(false)}
              className="mx-4 px-4 py-3 bg-primary text-primary-foreground text-center font-semibold rounded-lg flex items-center justify-center gap-2"
            >
              <Plus className="w-4 h-4" /> New Scan
            </Link>
          </div>
        )}
      </header>

      <main className="flex-1 pt-24 pb-12">
        {children}
      </main>

      <footer className="border-t border-white/5 py-12 mt-auto bg-card/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-2 opacity-50">
            <Shield className="w-5 h-5 text-foreground" />
            <span className="font-display font-bold tracking-tight text-foreground">SecScan</span>
          </div>
          <div className="flex flex-col sm:flex-row items-center gap-4 sm:gap-6">
            <nav className="flex items-center gap-5">
              <Link href="/privacy" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Privacy
              </Link>
              <Link href="/terms" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Terms
              </Link>
            </nav>
            <p className="text-sm text-muted-foreground">
              Your app is live. Is it safe? © {new Date().getFullYear()} SecScan
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
