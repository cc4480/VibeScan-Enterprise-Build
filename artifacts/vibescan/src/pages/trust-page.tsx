import { useEffect, useState } from "react";
import { Link, useRoute } from "wouter";
import { AlertCircle, Loader2, ShieldCheck } from "lucide-react";
import { useSeo } from "@/lib/seo";
import { cn, getGradeColor } from "@/lib/utils";
import { accentOrNull, coverageLine, findingsLine, freshness, heading, type TrustView } from "@/lib/trust-page";

/**
 * The public trust page for a domain: the owner's name and colour, the grade of the latest scan whose active tests ran, when
 * it was scanned, and how many findings of each kind, never what they are. Rendered without the app layout; no sign-in.
 * What may appear here is decided by the server (api-server lib/trustPageView.ts).
 */
export default function TrustPage() {
  const [, params] = useRoute("/trust/:domain");
  const domain = params?.domain ?? "";
  const [state, setState] = useState<{ view: TrustView } | { error: true } | null>(null);

  // A page its owner chose to publish, and still not one to index: the owner's own site is what links to it.
  useSeo({ title: `Security — ${domain} | SecScan`, description: `Security scan status for ${domain}, scanned by SecScan.`, noindex: true });

  useEffect(() => {
    let live = true;
    setState(null);
    fetch(`/api/trust/${encodeURIComponent(domain)}`)
      .then(async (res) => (res.ok ? { view: (await res.json()) as TrustView } : { error: true as const }))
      .catch(() => ({ error: true as const }))
      .then((s) => { if (live) setState(s); });
    return () => { live = false; };
  }, [domain]);

  if (!state) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }
  if ("error" in state) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4 max-w-md mx-auto px-4 text-center">
        <div className="w-16 h-16 rounded-full bg-secondary flex items-center justify-center"><AlertCircle className="w-8 h-8 text-muted-foreground" /></div>
        <h1 className="text-2xl font-bold">Not available</h1>
        <p className="text-muted-foreground leading-relaxed">This trust page is not available. It may be switched off, or its domain may no longer be verified.</p>
      </div>
    );
  }

  const v = state.view;
  const accent = accentOrNull(v.accent);
  const fresh = freshness(v.scannedAt, v.stale);
  const findings = findingsLine(v.findings);
  const coverage = coverageLine(v.coverage);

  return (
    <main className="min-h-screen px-4 py-12 flex justify-center">
      <div className="w-full max-w-2xl">
        <div className="glass-panel rounded-3xl p-8 sm:p-10 border-t-4" style={accent ? { borderTopColor: accent } : undefined}>
          <div className="flex items-center gap-3 mb-1">
            <ShieldCheck className="w-6 h-6 shrink-0" style={accent ? { color: accent } : undefined} />
            <h1 className="text-2xl sm:text-3xl font-bold break-words">{heading(v)}</h1>
          </div>
          {v.displayName && <p className="text-sm text-muted-foreground mb-6">{v.domain}</p>}

          <div className="flex items-center gap-6 mt-6">
            <div className={cn("text-7xl font-black leading-none", v.grade ? getGradeColor(v.grade) : "text-muted-foreground")}>{v.grade ?? "—"}</div>
            <div className="text-sm space-y-1.5">
              <div className={cn(fresh.warn && "text-amber-400 font-medium")}>{fresh.text}</div>
              {findings && <div className="text-muted-foreground">{findings}</div>}
              {coverage && <div className="text-muted-foreground">{coverage}</div>}
            </div>
          </div>

          <p className="text-xs text-muted-foreground leading-relaxed mt-8 pt-6 border-t border-white/10">
            This is the result of an automated security scan, including active tests that ran because the site's owner proved they control {v.domain}.
            It is a record of one scan at the time shown, not a certification or an audit, and the findings themselves are not published here.
          </p>
        </div>

        <p className="text-center text-sm text-muted-foreground mt-6">
          Scanned by <Link href="/about" className="text-primary hover:underline">SecScan</Link>
        </p>
      </div>
    </main>
  );
}
