import { Link } from "wouter";
import { motion } from "framer-motion";
import {
  ShieldAlert, Key, Globe, CheckCircle2, ArrowRight, Activity,
  Code2, Zap, Bell, Mail, Search, Bot, FileKey, Database, Network,
} from "lucide-react";
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
            <h2 className="text-3xl md:text-4xl font-bold mb-4">How Seclayer Works</h2>
            <p className="text-muted-foreground">Three steps to peace of mind.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-12 relative">
            <div className="hidden md:block absolute top-12 left-[15%] right-[15%] h-0.5 bg-gradient-to-r from-primary/0 via-primary/30 to-primary/0" />

            {[
              { step: 1, icon: Code2, title: "Paste Any URL", desc: "Drop in any publicly accessible URL — your own app, a client's site, or any live website." },
              { step: 2, icon: Zap, title: "We Scan", desc: "Our engine crawls your pages, probes for exposed files and secrets, checks SSL, DNS, headers, and runs 20+ active security tests — no agent needed." },
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

      {/* AI-Builder Callout Section */}
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
                VibeScan knows the specific risks that Lovable, Bolt, and Cursor-generated apps leave behind — including Supabase Row Level Security bypasses that expose your entire database to anonymous reads.
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

      {/* OWASP Coverage Section */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-4 uppercase tracking-wider">
            <Activity className="w-3.5 h-3.5" /> OWASP Top 10 Coverage
          </div>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">What Seclayer checks</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Every scan runs a comprehensive black-box suite targeting the most critical web security risks — without installing anything.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            {
              tag: "A01",
              tagColor: "text-primary",
              tagBg: "bg-primary/10 border-primary/20",
              title: "Broken Access Control",
              desc: "Checks for publicly exposed admin routes, directory listing, and missing auth enforcement on crawled pages.",
            },
            {
              tag: "A02",
              tagColor: "text-primary",
              tagBg: "bg-primary/10 border-primary/20",
              title: "Cryptographic Failures",
              desc: "SSL/TLS grade via Qualys SSL Labs, cipher strength, HSTS enforcement, and certificate validity.",
            },
            {
              tag: "A03",
              tagColor: "text-primary",
              tagBg: "bg-primary/10 border-primary/20",
              title: "Injection Risks",
              desc: "Detects input reflection patterns, missing content-type validation, and error verbosity on probed endpoints.",
            },
            {
              tag: "A05",
              tagColor: "text-primary",
              tagBg: "bg-primary/10 border-primary/20",
              title: "Security Misconfiguration",
              desc: "Security headers (CSP, X-Frame-Options, CORP, COOP), server version disclosure, debug modes, and open GraphQL introspection.",
            },
            {
              tag: "A06",
              tagColor: "text-primary",
              tagBg: "bg-primary/10 border-primary/20",
              title: "Vulnerable Components",
              desc: "Technology fingerprinting — detects 30+ frameworks, CDNs, and AI-builder platforms, then cross-references known CVEs.",
            },
            {
              tag: "A07",
              tagColor: "text-primary",
              tagBg: "bg-primary/10 border-primary/20",
              title: "Auth & Session Flaws",
              desc: "Cookie flags (HttpOnly, Secure, SameSite), session fixation indicators, and Supabase RLS bypass detection.",
            },
            {
              tag: "Files",
              tagColor: "text-orange-400",
              tagBg: "bg-orange-400/10 border-orange-400/20",
              title: "Exposed Secrets & Files",
              desc: "Actively probes for .env, .git/HEAD, .git/config, wp-config.php, phpinfo.php, backup.sql, and exposed API/OpenAPI specs.",
            },
            {
              tag: "DNS",
              tagColor: "text-blue-400",
              tagBg: "bg-blue-400/10 border-blue-400/20",
              title: "Email Security (SPF & DMARC)",
              desc: "Checks for missing or misconfigured SPF and DMARC records that let attackers send spoofed email from your domain.",
            },
            {
              tag: "Crawl",
              tagColor: "text-purple-400",
              tagBg: "bg-purple-400/10 border-purple-400/20",
              title: "Inner-Page Crawling",
              desc: "Follows internal links to check sub-pages for config leaks, debug logs, exposed API docs, and environment files — not just the root.",
            },
          ].map((item) => (
            <div key={item.tag} className="glass-card p-6 rounded-2xl flex gap-4 group hover:border-primary/30 transition-colors">
              <div className={cn("shrink-0 w-10 h-10 rounded-lg border flex items-center justify-center", item.tagBg)}>
                <span className={cn("font-mono text-xs font-bold", item.tagColor)}>{item.tag}</span>
              </div>
              <div>
                <h3 className="font-semibold text-foreground mb-1">{item.title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* What you get */}
      <section id="pricing" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-4 uppercase tracking-wider">
            <Zap className="w-3.5 h-3.5" /> Free Early Access
          </div>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Everything included, free right now</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">We're in early access. All scans and continuous monitoring are free while we fine-tune the platform.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto">
          {[
            {
              icon: Search,
              title: "Basic Scan",
              desc: "Core OWASP checks in minutes.",
              features: ["Security headers audit", "SSL/TLS grading", "Tech fingerprinting", "Letter grade A–F"],
              cta: "Run Basic Scan",
              href: "/scan",
              color: "text-primary",
              bg: "bg-primary/10",
              border: "",
            },
            {
              icon: Bot,
              title: "Deep Scan",
              desc: "Full analysis + AI remediation guide.",
              features: ["Everything in Basic", "Active path probing", "DNS & email security", "DeepSeek AI analysis", "Step-by-step fix guides"],
              cta: "Run Deep Scan",
              href: "/scan",
              color: "text-primary",
              bg: "bg-primary/10",
              border: "border-primary/50 shadow-[0_0_30px_rgba(20,184,120,0.1)]",
              popular: true,
            },
            {
              icon: Bell,
              title: "Continuous Monitor",
              desc: "Automated rescans + CVE alerts.",
              features: ["Weekly deep rescans", "Daily CVE feed monitoring", "Instant alerts for your stack", "Full AI report every run"],
              cta: "Start Monitoring",
              href: "/monitor",
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
                className={cn(
                  "w-full py-3 rounded-xl font-bold transition-all text-center block",
                  item.popular
                    ? "bg-primary text-primary-foreground hover:shadow-[0_0_20px_rgba(20,184,120,0.4)]"
                    : item.href === "/monitor"
                    ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-500/30"
                    : "bg-secondary text-foreground hover:bg-white/10",
                )}
              >
                {item.cta}
              </Link>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
