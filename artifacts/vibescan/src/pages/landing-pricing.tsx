import { Link } from "wouter";
import { CheckCircle2, Zap, Bell, Bot, Package } from "lucide-react";
import { cn } from "@/lib/utils";
import { BuyOptions, useBillingCatalog } from "@/components/billing-options";
import { fairUseText } from "@/lib/billing-api";

/** What you get, and the prices. */
export function PricingSection() {
  // The scan caps "unlimited" is subject to, from the server, so the card states what is enforced.
  const scanLimits = useBillingCatalog().data?.scanLimits;
  return (
    <section id="pricing" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-4 uppercase tracking-wider">
          <Zap className="w-3.5 h-3.5" /> Free Trial
        </div>
        <h2 className="text-3xl md:text-4xl font-bold mb-4">3 free scans every month, everything included</h2>
        <p className="text-muted-foreground max-w-2xl mx-auto">Every account gets 3 free scans a month, renewing on the 1st — every check, no tier to pick. The paid plan, with unlimited scans, is coming soon; we'll email you when it opens.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-3xl mx-auto">
        {[
          {
            icon: Bot,
            title: "Security Scan",
            desc: "Every check we have, on every scan, and nothing held back for paid accounts.",
            features: [
              "Headers, TLS and DNS",
              "Injection, XSS and path traversal",
              "API surface and access control",
              "AI analysis",
              "Step-by-step fix guides",
              "Every finding and fix unlocked, with no paywall on results",
              "Free re-tests to confirm a fix (10 a day, no scan used)",
              // Adding a site runs its first full scan, which a free account pays for with a free scan
              // (routes/monitorCreate.ts), so the line says so rather than calling the whole thing free.
              "Your first site watched free: hourly uptime, certificate and header checks, with email alerts (adding it uses one free scan)",
              "A grade badge for your README, for a site you have verified, showing only the grade and the scan date",
              "Scan from Claude Code, Cursor or the REST API on the same free scans",
            ],
            cta: "Run a Scan",
            href: "/scan",
            color: "text-primary",
            bg: "bg-primary/10",
            border: "border-primary/50 shadow-[0_0_30px_rgba(20,184,120,0.1)]",
            popular: true,
          },
          {
            icon: Bell,
            title: "Unlimited — $19/month",
            desc: "One plan: unlimited scans and 3 sites under continuous monitoring.",
            features: [
              `Unlimited full scans (${fairUseText(scanLimits)})`,
              "3 sites under continuous monitoring, around the clock",
              "Hourly uptime, header and certificate checks",
              "Hourly CVE matching, ranked by EPSS",
              "Rescans that follow your grade (A: 14d → F: 3d)",
              "Regression alerts to email, Slack, Discord and Teams, with quiet hours and your own rescan interval",
              "File findings as GitHub issues, Linear issues or Jira tickets, by click or automatically",
              "Evidence packs, public trust pages and your own report branding",
              "Cancel any time",
            ],
            cta: "See pricing",
            href: "#buy",
            color: "text-indigo-400",
            bg: "bg-indigo-400/10",
            border: "border-indigo-500/30",
          },
        ].map((item, i) => (
          <div key={i} className={cn("glass-panel p-8 rounded-2xl flex flex-col relative", item.border)}>
            {item.popular && (
              <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-primary text-primary-foreground px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider">
                Most Popular
              </div>
            )}
            <div className={cn("w-12 h-12 rounded-xl flex items-center justify-center mb-5", item.bg, item.color)}>
              <item.icon className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold mb-2">{item.title}</h3>
            <p className="text-sm text-muted-foreground pb-5 border-b border-white/10 mb-5">{item.desc}</p>
            <ul className="flex flex-col gap-2.5 mb-8 flex-1">
              {item.features.map((feat, j) => (
                <li key={j} className="flex items-start gap-2 text-sm">
                  <CheckCircle2 className={cn("w-4 h-4 shrink-0 mt-0.5", item.color)} />
                  <span>{feat}</span>
                </li>
              ))}
            </ul>
            <Link
              href={item.href}
              onClick={(e) => {
                // In-page anchor: scroll to the plans rather than route.
                if (item.href.startsWith("#")) {
                  e.preventDefault();
                  document.getElementById(item.href.slice(1))?.scrollIntoView({ behavior: "smooth" });
                }
              }}
              className={cn(
                "w-full py-3 rounded-xl font-bold transition-all text-center block",
                item.popular
                  ? "bg-primary text-primary-foreground hover:shadow-[0_0_20px_rgba(20,184,120,0.4)]"
                  : item.href === "#buy"
                  ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-500/30"
                  : "bg-secondary text-foreground hover:bg-white/10",
              )}
            >
              {item.cta}
            </Link>
          </div>
        ))}
      </div>

      <div id="buy" className="mt-14 max-w-5xl mx-auto scroll-mt-24">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-secondary border border-white/10 text-muted-foreground text-xs font-semibold mb-4 uppercase tracking-wider">
            <Package className="w-3.5 h-3.5" /> The plan
          </div>
          <h3 className="text-2xl md:text-3xl font-bold mb-3">Unlimited scans for $19 a month</h3>
          <p className="text-muted-foreground max-w-xl mx-auto text-sm">The paid plan is coming soon, with the same checks, AI report and fix guides. We'll email you when it opens.</p>
        </div>

        {/* Live Buy / Subscribe buttons once Stripe is configured; until then,
            the prices as information and an honest "not live yet". Prices in
            the live view come from the server, not from this file. */}
        <BuyOptions fallback={<StaticPricing />} />
      </div>
    </section>
  );
}

/** The price as information only — shown until checkout is switched on. */
function StaticPricing() {
  const scanLimits = useBillingCatalog().data?.scanLimits;
  return (
    <>
      <div className="max-w-sm mx-auto">
        <div className="glass-panel p-6 rounded-xl flex flex-col items-center text-center gap-1 border-primary/50">
          <span className="text-sm text-muted-foreground mt-1">SecScan Unlimited</span>
          <span className="text-3xl font-bold">$19</span>
          <span className="text-xs text-muted-foreground">per month · unlimited scans ({fairUseText(scanLimits)}) · 3 sites monitored</span>
        </div>
      </div>
      <p className="text-center text-xs text-muted-foreground mt-6">
        Purchasing isn't live yet — <Link href="/scan" className="underline hover:text-foreground">start with this month's 3 free scans</Link> and we'll email you when the plan is ready to buy.
      </p>
    </>
  );
}
