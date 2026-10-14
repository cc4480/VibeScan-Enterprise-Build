/** Severity badge, code block and the expandable check. */
import { useState } from "react";
import { Link } from "wouter";
import { Shield, ExternalLink, AlertTriangle, Info, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Severity, Check } from "./learn-types";
import { checkPath } from "./learn-checks";

// ─── Helpers ─────────────────────────────────────────────────────────────────

export const SEV_CONFIG: Record<Severity, { label: string; bg: string; text: string; border: string; dot: string; pill: string }> = {
  critical: { label: "Critical", bg: "bg-red-500/10",    text: "text-red-400",    border: "border-red-500/30",    dot: "bg-red-500",    pill: "bg-red-500/15 text-red-400 border-red-500/30" },
  high:     { label: "High",     bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30", dot: "bg-orange-500", pill: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  medium:   { label: "Medium",   bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/30", dot: "bg-yellow-500", pill: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" },
  low:      { label: "Low",      bg: "bg-blue-500/10",   text: "text-blue-400",   border: "border-blue-500/30",   dot: "bg-blue-500",   pill: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
  info:     { label: "Info",     bg: "bg-zinc-500/10",  text: "text-zinc-400",  border: "border-zinc-500/30",  dot: "bg-zinc-400",  pill: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30" },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg = SEV_CONFIG[severity];
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border", cfg.pill)}>
      <span className={cn("w-1.5 h-1.5 rounded-full", cfg.dot)} />
      {cfg.label}
    </span>
  );
}

export function CodeBlock({ code, lang }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <div className="relative mt-3">
      <div className="flex items-center justify-between bg-zinc-900 border border-white/10 rounded-t-lg px-4 py-2">
        <span className="text-xs text-zinc-500 font-mono">{lang ?? "code"}</span>
        <button onClick={copy} className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
      <pre className="bg-zinc-950 border border-t-0 border-white/10 rounded-b-lg p-4 overflow-x-auto text-sm text-zinc-300 leading-relaxed font-mono">
        <code>{code}</code>
      </pre>
    </div>
  );
}

export function CheckAccordion({ check }: { check: Check }) {
  const [open, setOpen] = useState(false);
  const cfg = SEV_CONFIG[check.severity];

  return (
    <div className={cn(
      "rounded-xl border transition-colors duration-200",
      open ? "border-white/10 bg-white/[0.03]" : "border-white/5 bg-white/[0.01] hover:border-white/10 hover:bg-white/[0.02]"
    )}>
      {/* Row header — always visible */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        <span className={cn("w-2 h-2 rounded-full shrink-0", cfg.dot)} />
        <span className="flex-1 font-medium text-foreground text-sm">{check.title}</span>
        <div className="flex items-center gap-3 shrink-0">
          <SeverityBadge severity={check.severity} />
          {check.cweId && (
            <span className="hidden sm:block text-xs text-muted-foreground font-mono">{check.cweId}</span>
          )}
          {check.cvssScore !== undefined && (
            <span className="hidden md:block text-xs text-muted-foreground font-mono">
              CVSS {check.cvssScore.toFixed(1)}
            </span>
          )}
          <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform duration-200", open && "rotate-180")} />
        </div>
      </button>

      {/* Expanded content */}
      {open && (
        <div className="px-5 pb-6 border-t border-white/5 mt-0 pt-5 space-y-5">
          {/* Meta badges */}
          <div className="flex flex-wrap gap-2">
            {check.owasp && (
              <span className="px-2.5 py-1 rounded-full bg-primary/10 border border-primary/20 text-xs text-primary font-semibold font-mono">
                OWASP {check.owasp}
              </span>
            )}
            {check.cweId && (
              <a
                href={`https://cwe.mitre.org/data/definitions/${check.cweId.replace("CWE-", "")}.html`}
                target="_blank" rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-muted-foreground hover:text-foreground transition-colors font-mono"
              >
                {check.cweId} <ExternalLink className="w-2.5 h-2.5" />
              </a>
            )}
            {check.wstgId && (
              <span className="px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-muted-foreground font-mono">
                {check.wstgId}
              </span>
            )}
          </div>

          {/* What it is */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/60 mb-2">What it is</p>
            <p className="text-sm text-muted-foreground leading-relaxed">{check.what}</p>
          </div>

          {/* Why it matters */}
          <div className="flex gap-3 p-4 rounded-xl bg-orange-500/5 border border-orange-500/20">
            <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-orange-400/70 mb-1">Why it matters</p>
              <p className="text-sm text-muted-foreground leading-relaxed">{check.why}</p>
            </div>
          </div>

          {/* How tested */}
          <div className="flex gap-3 p-4 rounded-xl bg-primary/5 border border-primary/20">
            <Shield className="w-4 h-4 text-primary shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-primary/70 mb-1">How SecScan tests this</p>
              <p className="text-sm text-muted-foreground leading-relaxed">{check.howTested}</p>
            </div>
          </div>

          {/* Fix */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/60 mb-2">How to fix it</p>
            <p className="text-sm text-muted-foreground leading-relaxed mb-1">{check.fix}</p>
            {check.fixCode && <CodeBlock code={check.fixCode} lang={check.fixCodeLang} />}
          </div>

          <Link href={checkPath(check.id)} className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline mr-4">
            Open this check on its own page
          </Link>

          {check.learnMore && (
            <a
              href={check.learnMore} target="_blank" rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
            >
              <Info className="w-3.5 h-3.5" /> Learn more <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      )}
    </div>
  );
}
