import { Link, useLocation } from "wouter";
import { useAuth } from "@workspace/replit-auth-web";
import { Shield, LogOut, ChevronRight, Menu, X } from "lucide-react";
import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, isAuthenticated, login, logout } = useAuth();
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
            : "bg-transparent border-transparent py-5"
        )}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-emerald-700 flex items-center justify-center shadow-lg shadow-primary/20 group-hover:shadow-primary/40 transition-all">
              <Shield className="w-5 h-5 text-primary-foreground" />
            </div>
            <span className="font-display font-bold text-xl tracking-tight text-foreground">
              VibeScan
            </span>
          </Link>

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center gap-8">
            <Link href="/" className={cn("text-sm font-medium transition-colors hover:text-foreground", location === "/" ? "text-foreground" : "text-muted-foreground")}>
              Home
            </Link>
            {isAuthenticated && (
              <Link href="/dashboard" className={cn("text-sm font-medium transition-colors hover:text-foreground", location === "/dashboard" ? "text-foreground" : "text-muted-foreground")}>
                Dashboard
              </Link>
            )}
            
            <div className="w-px h-6 bg-border" />
            
            {isAuthenticated ? (
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-secondary overflow-hidden border border-white/10">
                    {user?.profileImageUrl ? (
                      <img src={user.profileImageUrl} alt="Profile" className="w-full h-full object-cover" />
                    ) : (
                      <div className="w-full h-full flex items-center justify-center text-xs font-bold text-muted-foreground">
                        {user?.firstName?.[0] || user?.email?.[0] || '?'}
                      </div>
                    )}
                  </div>
                  <span className="text-sm font-medium text-foreground hidden lg:block">
                    {user?.firstName || 'User'}
                  </span>
                </div>
                <button 
                  onClick={() => logout()}
                  className="p-2 text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-colors"
                  title="Log out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
                <Link href="/scan" className="px-5 py-2.5 bg-primary text-primary-foreground text-sm font-semibold rounded-lg shadow-[0_0_15px_rgba(20,184,120,0.3)] hover:shadow-[0_0_25px_rgba(20,184,120,0.5)] hover:-translate-y-0.5 transition-all duration-200">
                  New Scan
                </Link>
              </div>
            ) : (
              <div className="flex items-center gap-4">
                <button 
                  onClick={() => login()}
                  className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
                >
                  Sign In
                </button>
                <button 
                  onClick={() => login()}
                  className="flex items-center gap-1 px-5 py-2.5 bg-white text-black text-sm font-semibold rounded-lg hover:bg-gray-100 hover:-translate-y-0.5 transition-all duration-200"
                >
                  Get Started <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            )}
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
          <div className="md:hidden absolute top-full left-0 right-0 bg-background/95 backdrop-blur-xl border-b border-white/5 py-4 px-4 flex flex-col gap-4 shadow-2xl">
            <Link href="/" onClick={() => setMobileMenuOpen(false)} className="px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary">Home</Link>
            {isAuthenticated && (
              <Link href="/dashboard" onClick={() => setMobileMenuOpen(false)} className="px-4 py-2 text-foreground font-medium rounded-lg hover:bg-secondary">Dashboard</Link>
            )}
            <div className="h-px bg-border my-2 mx-4" />
            {isAuthenticated ? (
              <>
                <Link href="/scan" onClick={() => setMobileMenuOpen(false)} className="mx-4 px-4 py-3 bg-primary text-primary-foreground text-center font-semibold rounded-lg">New Scan</Link>
                <button onClick={() => { logout(); setMobileMenuOpen(false); }} className="mx-4 px-4 py-3 bg-secondary text-foreground text-center font-semibold rounded-lg">Sign Out</button>
              </>
            ) : (
              <button onClick={() => login()} className="mx-4 px-4 py-3 bg-white text-black text-center font-semibold rounded-lg">Sign In / Get Started</button>
            )}
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
            <span className="font-display font-bold tracking-tight text-foreground">VibeScan</span>
          </div>
          <p className="text-sm text-muted-foreground">
            Your app is live. Is it safe? © {new Date().getFullYear()} VibeScan
          </p>
        </div>
      </footer>
    </div>
  );
}
