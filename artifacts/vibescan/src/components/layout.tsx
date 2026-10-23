import { Link, useLocation } from "wouter";
import { LayoutDashboard, Menu, X, Plus, BookOpen, Bell, Settings, ShieldCheck, MessageSquare } from "lucide-react";
import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { BREADCRUMBS, AccountNav } from "./layout-account-nav";

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
      {/* Background: the hero video's palette (deep blue, teal, emerald, a trace of lime) over the navy page colour, with a
          sparse starfield like the one in the video, so the page and the video do not clash. Decorative only. */}
      <div
        className="fixed inset-0 pointer-events-none z-[-1] overflow-hidden"
        aria-hidden="true"
        style={{
          // Its own compositor layer: painted once, not again as the page scrolls over it.
          transform: "translateZ(0)",
          willChange: "transform",
          backgroundImage: [
            "radial-gradient(50% 38% at 50% 24%, hsl(var(--video-teal) / 0.38), transparent 72%)",
            "radial-gradient(70% 55% at 8% 0%, hsl(var(--video-blue) / 0.85), transparent 70%)",
            "radial-gradient(55% 45% at 95% 18%, hsl(var(--video-teal) / 0.42), transparent 70%)",
            "radial-gradient(60% 50% at 12% 100%, hsl(var(--primary) / 0.22), transparent 70%)",
            "radial-gradient(40% 35% at 92% 100%, hsl(var(--video-lime) / 0.09), transparent 70%)",
            "linear-gradient(180deg, hsl(var(--video-navy)) 0%, hsl(var(--background)) 60%)",
          ].join(", "),
        }}
      >
        <div
          className="absolute inset-0 opacity-25"
          style={{
            backgroundImage:
              "radial-gradient(1px 1px at 20px 30px, rgba(190,255,235,.55), transparent), radial-gradient(1px 1px at 120px 110px, rgba(190,235,255,.45), transparent), radial-gradient(1.5px 1.5px at 170px 50px, rgba(190,255,235,.5), transparent)",
            backgroundSize: "211px 173px",
          }}
        />
        <div
          className="absolute inset-0 opacity-15"
          style={{
            backgroundImage:
              "radial-gradient(1px 1px at 60px 90px, rgba(200,255,225,.5), transparent), radial-gradient(1.5px 1.5px at 230px 160px, rgba(170,230,255,.45), transparent)",
            backgroundSize: "317px 251px",
          }}
        />
      </div>

      <header
        className={cn(
          "fixed top-0 left-0 right-0 z-50 transition-[padding,background-color,box-shadow] duration-300 border-b",
          scrolled
            ? "bg-background/95 border-white/5 shadow-lg shadow-black/20 py-3"
            : "bg-transparent border-transparent py-5",
        )}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group shrink-0">
            {/* The real mark, not the generic glyph. The artwork already carries
                its own dark ground and glow, so it needs no gradient tile behind
                it — just the rounded crop. */}
            <img
              src="/images/logo-80.webp?v=2"
              alt=""
              width={40}
              height={40}
              className="w-10 h-10 rounded-xl object-contain shadow-lg shadow-primary/20 group-hover:shadow-primary/40 transition-all"
            />
            <span className="font-display font-bold text-xl tracking-tight text-foreground">
              SecScan<span className="text-primary">.us</span>
            </span>
          </Link>

          {/* Desktop Nav */}
          {/* Signed in, the bar holds five links, the account, Sign out and New
              Scan. Below 1180px they do not fit, and they used to slide under the
              logo ("SecScanHome"), so the phone menu takes over until 1180px. The
              logo is the Home link here, so the bar does not repeat it. */}
          <nav className="hidden min-[1180px]:flex items-center gap-5 2xl:gap-7 whitespace-nowrap">
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

          {/* Mobile toggle. Labelled because it is icon-only and is the entire
              navigation on a phone — unlabelled, a screen reader announces it as
              just "button". */}
          <button
            type="button"
            className="min-[1180px]:hidden p-2 text-foreground"
            aria-label={mobileMenuOpen ? "Close menu" : "Open menu"}
            aria-expanded={mobileMenuOpen}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="min-[1180px]:hidden absolute top-full left-0 right-0 bg-background/95 border-b border-white/5 py-4 px-4 flex flex-col gap-3 shadow-2xl">
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
            <AccountNav mobile onNavigate={() => setMobileMenuOpen(false)} />
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
        {BREADCRUMBS[location] && (
          <nav aria-label="Breadcrumb" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-6">
            <ol className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <li>
                <Link href="/" className="hover:text-foreground transition-colors">Home</Link>
              </li>
              <li aria-hidden="true">›</li>
              <li aria-current="page" className="text-foreground">{BREADCRUMBS[location]}</li>
            </ol>
          </nav>
        )}
        {children}
      </main>

      {/* Feedback lives here rather than in the top bar, which it crowded into
          the logo. Every page, every screen size; hidden on the feedback page
          itself. */}
      {location !== "/feedback" && (
        <Link
          href="/feedback"
          title="Send feedback"
          className="group fixed bottom-5 right-5 z-40 flex items-center gap-2 h-11 pl-3.5 pr-4 rounded-full bg-card/95 border border-white/10 text-muted-foreground shadow-lg shadow-black/40 hover:text-foreground hover:border-primary/40 hover:shadow-primary/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary transition-all"
        >
          <MessageSquare className="w-[18px] h-[18px] text-primary/80 group-hover:text-primary transition-colors" />
          <span className="text-[13px] font-medium tracking-wide">Feedback</span>
        </Link>
      )}

      <footer className="border-t border-white/5 pt-12 pb-24 mt-auto bg-card/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-2 opacity-50">
            <img src="/images/logo-80.webp?v=2" alt="" width={20} height={20} className="w-5 h-5 rounded object-contain" />
            <span className="font-display font-bold tracking-tight text-foreground">SecScan.us</span>
          </div>
          <div className="flex flex-col sm:flex-row items-center gap-4 sm:gap-6">
            <nav className="flex items-center gap-5">
              <Link href="/learn" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Docs
              </Link>
              {/* secscan.info is the reference half of the same product and
                  links here throughout; without a link back the two domains
                  look related only in one direction. */}
              <a
                href="https://secscan.info"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Reference
              </a>
              <Link href="/about" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                About
              </Link>
              <Link href="/privacy" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Privacy
              </Link>
              <Link href="/terms" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                Terms
              </Link>
            </nav>
            <p className="text-sm text-muted-foreground">
              Your app is live. Is it safe? © {new Date().getFullYear()} SecScan.us
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}