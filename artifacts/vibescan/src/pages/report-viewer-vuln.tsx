/** One finding, expanded. */
import { CheckCircle2, Globe, Package, HelpCircle, Flag, RotateCcw } from "lucide-react";
import { cn, getSeverityColors } from "@/lib/utils";
import { VerifyFixButton } from "@/components/verify-fix-button";
import { GithubIssueButton } from "@/components/github-issue-button";
import { TicketButtons } from "@/components/ticket-buttons";
import { motion, AnimatePresence } from "framer-motion";
import { useState, useContext } from "react";
import type { Vulnerability } from "@workspace/api-client-react";
import { ReproSteps } from "@/components/repro-steps";
import { hasFindingActions } from "@/lib/scan-notes";
import { FindingProvenance } from "./report-viewer-provenance";
import { DismissalsContext, vulnUniqueKey, getCategoryMeta, parseTechVersion, extractInnerPageSource, getVerificationNote, wstgCategoryPath } from "./report-viewer-data";

// ─── Vuln card ────────────────────────────────────────────────────────────────

/** How many finding cards fade in on load; the rest render at once. */
export const FADE_IN_CARDS = 8;

export function VulnCard({
  vuln,
  index,
  needsVerification,
  rootUrl,
}: {
  vuln: Vulnerability;
  index: number;
  needsVerification?: boolean;
  rootUrl?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const { dismiss, undismiss, dismissedFps, vulnFpMap, optimisticDismissKeys } = useContext(DismissalsContext);
  const vKey = vulnUniqueKey(vuln);
  const fp = vulnFpMap.get(vKey);
  const isDismissed = optimisticDismissKeys.has(vKey) || (fp !== undefined && dismissedFps.has(fp));
  const [dismissPending, setDismissPending] = useState(false);
  const meta = getCategoryMeta(vuln.category);

  // Extract the affected component for CVE / outdated-software findings.
  // Hoisted here so both the header chip and the expanded detail share the same value.
  const isCveCategory =
    vuln.category === "Outdated Software / Known CVE" ||
    vuln.category === "Outdated Software";
  const rawComponent = isCveCategory
    ? (/^(.+?)\s+—/.exec(vuln.name)?.[1] ??
       /^Detected:\s+(.+)$/m.exec(vuln.evidence ?? "")?.[1] ??
       null)
    : null;
  const { name: compName, version: compVersion } = rawComponent
    ? parseTechVersion(rawComponent)
    : { name: null, version: null };

  // Extract inner-page source path (e.g. "/api/v1") for crawler findings
  // Only shown for Security Header Inconsistency and Session Management categories
  const innerPageSource = rootUrl
    ? extractInnerPageSource(vuln.evidence, rootUrl, vuln.category)
    : null;

  return (
    <motion.div
      // Only the first screenful fades in. A card that starts invisible stays blank until its animation runs, and a browser
      // pauses animations in a tab that is not showing (a report opened from the progress page while you are elsewhere), so on
      // a list of dozens the rest would sit as empty gaps. Cards further down are simply there.
      initial={index < FADE_IN_CARDS ? { opacity: 0, y: 20 } : false}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(0.05 * index, 0.4) }}
      className="glass-flat rounded-xl overflow-hidden border border-white/5"
      style={{ borderLeft: `3px solid ${meta.color}` }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-5 flex items-start sm:items-center justify-between text-left hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex flex-col sm:flex-row sm:items-center gap-3 flex-1 min-w-0">
          <span className={cn("px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider shrink-0 border", getSeverityColors(vuln.severity))}>
            {vuln.severity}
          </span>
          <div className="flex flex-col sm:flex-row sm:items-center gap-1.5 min-w-0">
            <h4 className="text-base font-bold text-foreground leading-snug">{vuln.name}</h4>
            {compName && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-yellow-500/10 border border-yellow-500/20 rounded text-[10px] font-mono leading-none text-yellow-400/80 shrink-0 self-start sm:self-auto">
                <Package className="w-2.5 h-2.5" />
                {compName}{compVersion ? `@${compVersion}` : ""}
              </span>
            )}
            {innerPageSource && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-sky-500/10 border border-sky-500/20 rounded text-[10px] font-mono leading-none text-sky-400/70 shrink-0 self-start sm:self-auto" title={`Found on inner page: ${innerPageSource}`}>
                <Globe className="w-2.5 h-2.5" />
                {innerPageSource}
              </span>
            )}
          </div>
        </div>
        <div className="hidden md:flex items-center gap-1.5 text-xs font-medium shrink-0 ml-4" style={{ color: meta.color }}>
          {meta.icon}
          <span className="whitespace-nowrap">{meta.label}</span>
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="p-5 pt-0 border-t border-white/5 mt-2 bg-secondary/20">
              {needsVerification && (
                <div className="mt-4 mb-1 flex gap-3 p-3 rounded-lg bg-amber-500/8 border border-amber-500/25">
                  <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-semibold text-amber-300 mb-0.5">Manual verification recommended</p>
                    <p className="text-xs text-amber-200/70 leading-relaxed">{getVerificationNote(vuln.category)}</p>
                  </div>
                </div>
              )}
              {/* Detected component badge for CVE/outdated-software findings */}
              {compName && (
                <div className="mt-4 flex items-center gap-2">
                  <span className="text-xs text-muted-foreground font-medium">Detected component:</span>
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-secondary rounded-md border border-white/10 text-xs font-mono">
                    <Package className="w-3 h-3 text-yellow-400 shrink-0" />
                    <span className="font-medium text-foreground/90">{compName}</span>
                    {compVersion && (
                      <span className="px-1.5 py-0.5 bg-yellow-500/15 text-yellow-400 text-[10px] rounded border border-yellow-500/20 leading-none font-mono">
                        {compVersion}
                      </span>
                    )}
                  </span>
                </div>
              )}

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-5">
                <div className="flex flex-col gap-4">
                  <div>
                    <h5 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">Description</h5>
                    <p className="text-sm text-foreground/90 leading-relaxed">{vuln.description}</p>
                  </div>
                  {vuln.evidence && (
                    <div>
                      <h5 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">Evidence: what the scanner saw</h5>
                      <div className="bg-background border border-white/10 rounded-lg p-3 text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap">
                        {vuln.evidence}
                      </div>
                    </div>
                  )}
                  <ReproSteps evidence={vuln.evidence} dark />
                  <FindingProvenance vuln={vuln} />
                </div>
                <div>
                  <h5 className="text-xs font-bold text-primary uppercase tracking-wider mb-2 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" /> Recommended Fix
                  </h5>
                  <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 text-sm text-foreground/90 leading-relaxed">
                    <div className="whitespace-pre-wrap">{vuln.solution}</div>
                  </div>
                  {hasFindingActions(vuln) && <VerifyFixButton findingId={vuln.id} />}
                  {hasFindingActions(vuln) && <GithubIssueButton findingId={vuln.id} />}
                  {hasFindingActions(vuln) && <TicketButtons findingId={vuln.id} />}

                  {(vuln.cweId || vuln.cvssScore != null || vuln.wstgId || vuln.confidence != null) && (
                    <div className="mt-4 flex gap-3 flex-wrap">
                      {vuln.cweId && (
                        <a
                          href={`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace("CWE-", "")}.html`}
                          target="_blank" rel="noreferrer"
                          className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded hover:bg-secondary/80 transition-colors"
                        >
                          {vuln.cweId}
                        </a>
                      )}
                      {vuln.cvssScore != null && (
                        <span className={cn(
                          "text-xs px-2 py-1 rounded font-medium",
                          vuln.cvssScore >= 9 ? "bg-red-950 text-red-400" :
                          vuln.cvssScore >= 7 ? "bg-orange-950 text-orange-400" :
                          vuln.cvssScore >= 4 ? "bg-yellow-950 text-yellow-400" :
                          "bg-secondary text-muted-foreground",
                        )}>
                          CVSS {vuln.cvssScore.toFixed(1)}
                        </span>
                      )}
                      {vuln.wstgId && (
                        <a
                          href={`https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/${wstgCategoryPath(vuln.wstgId)}`}
                          target="_blank" rel="noreferrer"
                          className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded hover:bg-secondary/80 transition-colors"
                        >
                          {vuln.wstgId}
                        </a>
                      )}
                      {vuln.confidence != null && (
                        <span
                          title="Confidence: how certain the scanner is this is a real finding, not a false positive"
                          className={cn(
                            "text-xs px-2 py-1 rounded font-medium",
                            vuln.confidence >= 85 ? "bg-green-950 text-green-400" :
                            vuln.confidence >= 70 ? "bg-green-950 text-green-400" :
                            vuln.confidence >= 55 ? "bg-yellow-950 text-yellow-500" :
                            "bg-secondary text-muted-foreground",
                          )}
                        >
                          {vuln.confidence}% confidence
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* False positive dismissal. A scan note is not a finding, so it has none. */}
            {hasFindingActions(vuln) && (
            <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
              <p className="text-xs text-muted-foreground">Not applicable to your setup?</p>
              {isDismissed ? (
                <button
                  onClick={async (e) => {
                    e.stopPropagation();
                    setDismissPending(true);
                    await undismiss(vuln);
                    setDismissPending(false);
                  }}
                  disabled={dismissPending}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-green-500/10 border border-green-500/20 text-green-400 hover:bg-green-500/20 transition-colors disabled:opacity-50"
                >
                  <RotateCcw className="w-3 h-3" />
                  Undo dismissal
                </button>
              ) : (
                <button
                  onClick={async (e) => {
                    e.stopPropagation();
                    if (!rootUrl) return;
                    setDismissPending(true);
                    await dismiss(vuln, rootUrl);
                    setDismissPending(false);
                  }}
                  disabled={dismissPending || !rootUrl}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-secondary border border-white/10 text-muted-foreground hover:text-foreground hover:border-white/20 transition-colors disabled:opacity-50"
                >
                  <Flag className="w-3 h-3" />
                  Mark as false positive
                </button>
              )}
            </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
