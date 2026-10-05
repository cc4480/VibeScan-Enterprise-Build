import { Link } from "wouter";
import { ArrowRight, Activity, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";

/** Using SecScan from an AI editor over MCP. */
export function McpSection() {
  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 lg:gap-14 items-center">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-6 uppercase tracking-wider">
            <Terminal className="w-3.5 h-3.5" /> Works in your AI editor
          </div>
          <h2 className="text-3xl md:text-4xl font-bold mb-5">
            Scan and fix without<br />
            <span className="text-gradient-primary">leaving your editor.</span>
          </h2>
          <p className="text-muted-foreground mb-6 text-lg leading-relaxed">
            Connect SecScan to Claude Code, Cursor or any MCP-capable editor. Ask it to scan your site, and it reads
            the report and starts on the fixes — same checks, same limits, no copy and paste.
          </p>
          <ol className="space-y-3 mb-8 text-sm">
            {[
              "Create a token in Settings → AI editors",
              "Paste the one-line setup command into your editor",
              "Ask: “scan my site with SecScan and fix what's urgent”",
            ].map((step, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-primary/15 text-primary text-xs font-bold flex items-center justify-center shrink-0">
                  {i + 1}
                </span>
                <span className="pt-0.5">{step}</span>
              </li>
            ))}
          </ol>
          <Link
            href="/settings#ai-editors"
            className="inline-flex items-center gap-2 px-6 py-3 bg-secondary text-foreground border border-white/10 font-bold rounded-xl hover:bg-white/10 transition-all"
          >
            Connect your editor <ArrowRight className="w-4 h-4" />
          </Link>
        </div>

        {/* An illustration of the flow, not a transcript of a real site. */}
        <figure className="glass-panel rounded-2xl border border-white/10 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/10 bg-background/40">
            <span className="w-2.5 h-2.5 rounded-full bg-red-400/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-400/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-green-400/60" />
            <span className="ml-2 text-xs text-muted-foreground font-mono">your editor · example</span>
          </div>
          <div className="p-5 space-y-4 font-mono text-[13px] leading-relaxed">
            <p><span className="text-primary">you ›</span> scan my site with SecScan and fix what's urgent</p>
            <p className="text-muted-foreground">⏺ secscan · scan_url <span className="text-foreground/70">app.example.com</span></p>
            <p className="text-muted-foreground">⏺ secscan · get_scan_status <span className="text-foreground/70">— done in 24s</span></p>
            <p>
              Grade <span className="text-yellow-300 font-bold">C</span> — 2 high, 3 medium. Most urgent:{" "}
              <span className="text-foreground">your .env file is publicly readable</span>. Blocking dotfiles in
              the server config now, then rotating the keys it exposed…
            </p>
          </div>
          <figcaption className="px-5 pb-4 text-[11px] text-muted-foreground">
            Example session. Scans follow the same rules as the website: they use your free scans, or your
            plan if you have one, and active tests run only on domains you've verified.
          </figcaption>
        </figure>
      </div>
    </section>
  );
}

/** OWASP Top 10 coverage. */
export function OwaspSection() {
  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-4 uppercase tracking-wider">
          <Activity className="w-3.5 h-3.5" /> OWASP Top 10-Aligned
        </div>
        <h2 className="text-3xl md:text-4xl font-bold mb-4">What SecScan checks</h2>
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
            desc: "TLS configuration check (protocol versions, cipher strength, certificate validity and trust), plus HSTS enforcement.",
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
  );
}

