import { Link } from "wouter";
import { motion } from "framer-motion";
import { ShieldAlert, Key, Globe, CheckCircle2, ArrowRight, Activity, Code2, Zap, Bell } from "lucide-react";
import { cn } from "@/lib/utils";

export default function LandingPage() {
  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring" as const, stiffness: 300, damping: 24 } }
  };

  return (
    <div className="flex flex-col gap-24 lg:gap-32">
      {/* Hero Section */}
      <section className="relative pt-12 pb-20 lg:pt-24 lg:pb-32 overflow-hidden">
        <div className="absolute inset-0 z-0">
          <img
            src={`${import.meta.env.BASE_URL}images/hero-bg.png`}
            alt="Cyber security background"
            className="w-full h-full object-cover opacity-30 mix-blend-screen"
          />
          <div className="absolute inset-0 bg-gradient-to-b from-background/10 via-background/80 to-background" />
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="show"
            className="max-w-3xl mx-auto text-center flex flex-col items-center"
          >
            <motion.div variants={itemVariants} className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-8">
              <Activity className="w-4 h-4" />
              <span>DeepSeek AI Analysis Engine v1.0</span>
            </motion.div>

            <motion.h1 variants={itemVariants} className="text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-6">
              Any website. <br />
              <span className="text-gradient-primary">Is it safe?</span>
            </motion.h1>

            <motion.p variants={itemVariants} className="text-lg md:text-xl text-muted-foreground mb-10 max-w-2xl">
              Paste any public URL — your app, a client's site, or a competitor's — and get a plain-English security report in under 10 minutes. No installs, no agents.
            </motion.p>

            <motion.div variants={itemVariants} className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto">
              <Link
                href="/scan"
                className="w-full sm:w-auto px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] hover:-translate-y-1 transition-all duration-300 flex items-center justify-center gap-2"
              >
                Scan Your App <ArrowRight className="w-5 h-5" />
              </Link>
              <a
                href="#pricing"
                className="w-full sm:w-auto px-8 py-4 bg-secondary text-foreground text-lg font-semibold rounded-xl border border-white/5 hover:bg-secondary/80 transition-all duration-300 text-center"
              >
                View Pricing
              </a>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* Problem Section */}
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

      {/* How it works */}
      <section className="bg-card/30 border-y border-white/5 py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">How VibeScan Works</h2>
            <p className="text-muted-foreground">Three steps to peace of mind.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-12 relative">
            <div className="hidden md:block absolute top-12 left-[15%] right-[15%] h-0.5 bg-gradient-to-r from-primary/0 via-primary/30 to-primary/0" />

            {[
              { step: 1, icon: Code2, title: "Paste Any URL", desc: "Drop in any publicly accessible URL — your own app, a client's site, or any live website." },
              { step: 2, icon: Zap, title: "We Scan", desc: "Our engine analyzes headers, SSL, and runs a comprehensive black-box check." },
              { step: 3, icon: CheckCircle2, title: "Get Report", desc: "DeepSeek AI translates the raw findings into a plain-English, actionable report." }
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

      {/* OWASP Coverage Section */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-4 uppercase tracking-wider">
            <Activity className="w-3.5 h-3.5" /> OWASP Top 10 Coverage
          </div>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">What VibeScan checks</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Every scan runs a comprehensive black-box suite targeting the most critical web security risks—without installing anything.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { category: "A01", title: "Broken Access Control", desc: "Checks for publicly exposed admin routes, directory listing, and missing auth enforcement." },
            { category: "A02", title: "Cryptographic Failures", desc: "SSL/TLS grade, cipher strength, HSTS enforcement, and certificate validity." },
            { category: "A03", title: "Injection Risks", desc: "Detects input reflection patterns, missing content-type validation, and error verbosity." },
            { category: "A05", title: "Security Misconfiguration", desc: "Security headers (CSP, X-Frame-Options, CORP, COOP), server version disclosure, debug modes." },
            { category: "A06", title: "Vulnerable Components", desc: "Technology fingerprinting to identify outdated frameworks and libraries in use." },
            { category: "A07", title: "Auth & Session Flaws", desc: "Cookie flags (HttpOnly, Secure, SameSite), session fixation indicators, and login endpoint analysis." },
          ].map((item) => (
            <div key={item.category} className="glass-card p-6 rounded-2xl flex gap-4 group hover:border-primary/30 transition-colors">
              <div className="shrink-0 w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
                <span className="text-primary font-mono text-xs font-bold">{item.category}</span>
              </div>
              <div>
                <h3 className="font-semibold text-foreground mb-1">{item.title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Pay only when you scan</h2>
          <p className="text-muted-foreground">No monthly subscriptions. Buy single scans, save with a pack, or monitor continuously.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6">
          {[
            { name: "Basic Scan", price: "$9", period: null, desc: "Core checks + Supabase RLS test.", features: ["Header analysis", "SSL/TLS grading", "Tech fingerprint", "Supabase RLS check", "Letter grade & score"], cta: "Buy Basic", highlight: false, monitor: false },
            { name: "Deep Scan", price: "$19", period: null, desc: "Full pentest with per-agent fix prompt.", features: ["Everything in Basic", "JS secret scanning", "DeepSeek AI analysis", "Per-agent fix prompt (Cursor / Claude Code / Lovable)"], cta: "Buy Deep", highlight: true, monitor: false },
            { name: "5-Scan Pack", price: "$79", period: null, desc: "5 Deep Scans — save $16.", features: ["5× Deep Scan credits", "Credits never expire", "Use on any project", "Priority queue"], cta: "Get 5 Pack", highlight: false, monitor: false },
            { name: "20-Scan Pack", price: "$199", period: null, desc: "For agencies — save $181.", features: ["20× Deep Scan credits", "Highest priority queue", "API access (soon)", "White-label reports (soon)"], cta: "Get 20 Pack", highlight: false, monitor: false },
            { name: "Monitor", price: "$49", period: "/mo", desc: "Continuous anti-regression scanning.", features: ["Weekly deep rescans", "Daily CVE feed monitoring", "Instant alerts when new CVEs match your stack", "Re-scan after every vibe-coding session"], cta: "Start Monitoring", highlight: false, monitor: true },
          ].map((tier, i) => (
            <div key={i} className={cn("glass-panel p-8 rounded-2xl flex flex-col", tier.highlight ? "border-primary/50 relative transform md:-translate-y-4 shadow-[0_0_30px_rgba(20,184,120,0.1)]" : "", tier.monitor ? "border-indigo-500/30 bg-indigo-500/5" : "")}>
              {tier.highlight && (
                <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-primary text-primary-foreground px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider">
                  Most Popular
                </div>
              )}
              {tier.monitor && (
                <div className="flex items-center gap-1.5 mb-3">
                  <Bell className="w-4 h-4 text-indigo-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-indigo-400">Always-On</span>
                </div>
              )}
              <h3 className="text-xl font-bold mb-2">{tier.name}</h3>
              <div className="flex items-baseline gap-1 mb-4">
                <span className="text-4xl font-black">{tier.price}</span>
                {tier.period && <span className="text-muted-foreground text-sm">{tier.period}</span>}
              </div>
              <p className="text-sm text-muted-foreground pb-6 border-b border-white/10 mb-6">{tier.desc}</p>

              <ul className="flex flex-col gap-3 mb-8 flex-1">
                {tier.features.map((feat, j) => (
                  <li key={j} className="flex items-start gap-2 text-sm">
                    <CheckCircle2 className={cn("w-5 h-5 shrink-0", tier.monitor ? "text-indigo-400" : "text-primary")} />
                    <span>{feat}</span>
                  </li>
                ))}
              </ul>

              <Link
                href={tier.monitor ? "/monitor" : "/scan"}
                className={cn("w-full py-3 rounded-xl font-bold transition-all text-center block",
                  tier.highlight ? "bg-primary text-primary-foreground hover:shadow-[0_0_20px_rgba(20,184,120,0.4)]"
                  : tier.monitor ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-500/30"
                  : "bg-secondary text-foreground hover:bg-white/10")}
              >
                {tier.cta}
              </Link>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
