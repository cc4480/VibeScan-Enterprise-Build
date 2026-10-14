import { Link } from "wouter";
import { ShieldAlert, Key, Globe, CheckCircle2, ArrowRight, Code2, Zap, Bot, FileKey, Database, Network } from "lucide-react";
import { cn } from "@/lib/utils";

// The hero lives in landing-hero.tsx; re-exported so landing.tsx imports are unchanged.
export { HeroSection } from "./landing-hero";

/** Why AI-built apps ship with holes. */
export function ProblemSection() {
  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-16">
        <h2 className="text-3xl md:text-4xl font-bold mb-4">Common failures in fast-shipped apps</h2>
        <p className="text-muted-foreground max-w-2xl mx-auto">AI code generators are great for features, but they consistently miss security fundamentals. Don't let your launch turn into a breach.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {[
          { icon: Key, title: "Exposed API Keys", desc: "Hardcoded credentials in client bundles or public endpoints without rate limiting.", color: "text-red-400", bg: "bg-red-400/10" },
          { icon: ShieldAlert, title: "Missing Auth Checks", desc: "Routes that assume the frontend will hide them, leaving the API completely open.", color: "text-orange-400", bg: "bg-orange-400/10" },
          { icon: Globe, title: "No Security Headers", desc: "Missing CSP, HSTS, and frame options making your app vulnerable to XSS and clickjacking.", color: "text-yellow-400", bg: "bg-yellow-400/10" }
        ].map((item, i) => (
          <div key={i} className="glass-card p-8 rounded-2xl">
            <div className={cn("w-12 h-12 rounded-xl flex items-center justify-center mb-6", item.bg, item.color)}>
              <item.icon className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold mb-3">{item.title}</h3>
            <p className="text-muted-foreground">{item.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

/** How a scan works, step by step. */
export function HowItWorksSection() {
  return (
    <section className="bg-card/30 border-y border-white/5 py-24">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">How SecScan Works</h2>
          <p className="text-muted-foreground">Three steps to peace of mind.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-12 relative">
          <div className="hidden md:block absolute top-12 left-[15%] right-[15%] h-0.5 bg-gradient-to-r from-primary/0 via-primary/30 to-primary/0" />

          {[
            { step: 1, icon: Code2, title: "Paste Any URL", desc: "Drop in any publicly accessible URL — your own app, a client's site, or any live website." },
            { step: 2, icon: Zap, title: "We Scan", desc: "Our engine crawls your pages, probes for exposed files and secrets, checks SSL, DNS, headers, and, on a domain you have verified, runs active security tests — no agent needed." },
            { step: 3, icon: CheckCircle2, title: "Get Report", desc: "Our AI translates the raw findings into a plain-English, actionable report." }
          ].map((item, i) => (
            <div key={i} className="relative flex flex-col items-center text-center">
              <div className="w-24 h-24 rounded-full bg-background border-2 border-primary/30 flex items-center justify-center mb-6 shadow-[0_0_20px_rgba(20,184,120,0.1)] relative z-10">
                <item.icon className="w-10 h-10 text-primary" />
                <div className="absolute -top-2 -right-2 w-8 h-8 rounded-full bg-primary text-background font-bold flex items-center justify-center border-4 border-background">
                  {item.step}
                </div>
              </div>
              <h3 className="text-xl font-bold mb-3">{item.title}</h3>
              <p className="text-muted-foreground">{item.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/** The callout for people building with AI tools. */
export function AiBuilderSection() {
  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="glass-panel rounded-3xl p-10 lg:p-16 border-primary/20 bg-primary/5 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-primary/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 pointer-events-none" />
        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-6 uppercase tracking-wider">
              <Bot className="w-3.5 h-3.5" /> Built for AI-generated apps
            </div>
            <h2 className="text-3xl md:text-4xl font-bold mb-5">
              AI builders ship fast.<br />
              <span className="text-gradient-primary">Security gaps come free.</span>
            </h2>
            <p className="text-muted-foreground mb-8 text-lg leading-relaxed">
              SecScan knows the specific risks that Lovable, Bolt, and Cursor-generated apps leave behind — including Supabase Row Level Security bypasses that expose your entire database to anonymous reads.
            </p>
            <Link
              href="/scan"
              className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground font-bold rounded-xl hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] transition-all"
            >
              Scan Your App Now <ArrowRight className="w-4 h-4" />
            </Link>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {[
              {
                icon: Database,
                color: "text-red-400",
                bg: "bg-red-400/10",
                title: "Supabase RLS Bypass",
                desc: "Detects tables that return rows to unauthenticated requests because Row Level Security is disabled.",
              },
              {
                icon: FileKey,
                color: "text-orange-400",
                bg: "bg-orange-400/10",
                title: "service_role Key Leak",
                desc: "Finds Supabase service_role JWTs embedded in client-side code — they bypass all RLS policies (CVSS 10.0).",
              },
              {
                icon: Bot,
                color: "text-blue-400",
                bg: "bg-blue-400/10",
                title: "AI-Builder Detection",
                desc: "Identifies apps built with Lovable, Bolt.new, Cursor, Firebase, and more — then applies targeted checks.",
              },
              {
                icon: Network,
                color: "text-purple-400",
                bg: "bg-purple-400/10",
                title: "GraphQL Introspection",
                desc: "Detects exposed GraphQL endpoints where schema introspection is left open — a common AI-scaffolded API mistake.",
              },
            ].map((item, i) => (
              <div key={i} className="glass-card p-5 rounded-2xl flex flex-col gap-3">
                <div className={cn("w-10 h-10 rounded-xl flex items-center justify-center shrink-0", item.bg, item.color)}>
                  <item.icon className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-semibold text-sm mb-1">{item.title}</h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

