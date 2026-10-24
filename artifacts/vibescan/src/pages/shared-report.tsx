import { SharedReportLoading, SharedReportError } from "./shared-report-states";
import { useSharedReportData, useSharedReportPdf } from "./shared-report-hooks";
import { useRoute, Link } from "wouter";
import { useSeo } from "@/lib/seo";
import { Shield, Globe, Lock, Loader2, Download, Share2, Info } from "lucide-react";
import { cn, getGradeColor } from "@/lib/utils";
import { APP_ORIGIN } from "@/lib/origin";
import { brandOf, sharedFooter } from "@/lib/branding";
import { NO_FINDINGS_WITH_NOTES, SCAN_NOTES_BLURB, SCAN_NOTES_TITLE, scanNotesCount, splitScanNotes } from "@/lib/scan-notes";
import { PdfReport } from "@/components/pdf-report";
import { GradeRing, VulnRow, ComplianceCard, CoverageCard, SourceCodeCard, SeverityLegend, SEV_ORDER, VERIFICATION_THRESHOLD } from "./shared-report-components";
import { WithheldCard, type Interception } from "./report-viewer-provenance";

export default function SharedReport() {
  const [, params] = useRoute("/share/:token");
  const token = params?.token ?? "";

  const { report, loading, error } = useSharedReportData(token);

  // A report from an account with report branding says who prepared it, and may drop SecScan's own name (lib/branding.ts).
  const brand = brandOf(report);
  const foot = sharedFooter(brand);
  const siteName = brand && !brand.poweredBy ? brand.name : "SecScan.us";

  const seoTitle = report
    ? `Grade ${report.data.summary.grade} — ${(() => { try { return new URL(report.targetUrl).hostname; } catch { return report.targetUrl; } })()} | ${siteName} Security Report`
    : "Security Report — SecScan.us";
  const seoDescription = report
    ? `Security scan of ${report.targetUrl}: Grade ${report.data.summary.grade}, risk score ${report.data.summary.riskScore}/100, ${report.data.summary.totalVulnerabilities} finding${report.data.summary.totalVulnerabilities !== 1 ? "s" : ""}.${foot.showSecScanCredit ? " Powered by SecScan." : ""}`
    : "View this security scan report powered by SecScan — automated black-box security scanning for web applications.";
  useSeo({ title: seoTitle, description: seoDescription, canonical: `${APP_ORIGIN}/share/${token}` });

  const { pdfContainerRef, generatingPdf, showPdfContainer, handleDownloadPDF } = useSharedReportPdf(report);

  if (loading) return <SharedReportLoading />;
  if (error) return <SharedReportError error={error} />;

  if (!report) return null;

  const { data } = report;
  const { summary, vulnerabilities, technologies, server, tlsGrade, aiAnalysis, compliance } = data;

  // The scan's own notes are not findings: they are listed apart, under "About this scan".
  const { findings, notes } = splitScanNotes(vulnerabilities);
  const bySeverity = (a: { severity: string }, b: { severity: string }) => (SEV_ORDER[a.severity] ?? 99) - (SEV_ORDER[b.severity] ?? 99);
  const sorted = [...findings].sort(bySeverity);
  const scanNotes = [...notes].sort(bySeverity);
  const confirmed = sorted.filter((v) => (v.confidence ?? 100) >= VERIFICATION_THRESHOLD);
  const unverified = sorted.filter((v) => (v.confidence ?? 100) < VERIFICATION_THRESHOLD);

  const dateStr = new Date(report.scannedAt).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric",
  });

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 pb-24">
      <div className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-secondary/50 border border-white/5 text-xs text-muted-foreground">
          <Share2 className="w-3.5 h-3.5" />
          Shared report — read only
        </div>
        <button
          onClick={() => void handleDownloadPDF()}
          disabled={generatingPdf}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors disabled:opacity-60"
        >
          {generatingPdf ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
          {generatingPdf ? "Generating…" : "Download PDF"}
        </button>
      </div>

      <div className="glass-panel p-6 md:p-10 rounded-3xl mb-10 relative overflow-hidden flex flex-col sm:flex-row items-center gap-8">
        <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-primary/5 rounded-full blur-[100px] pointer-events-none" />
        <div className="z-10 shrink-0">
          <GradeRing grade={summary.grade} score={summary.riskScore} />
        </div>
        <div className="flex-1 text-center sm:text-left z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary border border-white/5 text-xs font-medium text-muted-foreground mb-4">
            <Globe className="w-3.5 h-3.5" /> {report.targetUrl}
          </div>
          <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">Security Report</h1>
          <p className="text-base text-muted-foreground/80 leading-relaxed max-w-xl">
            {summary.executiveSummary}
          </p>
          <div className="mt-4">
            <SeverityLegend counts={summary} />
          </div>
          <p className="text-xs text-muted-foreground/50 mt-3">Scanned {dateStr}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          <h2 className="text-xl font-bold border-b border-white/10 pb-4">
            Identified Vulnerabilities
            <span className="bg-secondary text-foreground text-sm py-1 px-3 rounded-full ml-3">{findings.length}</span>
          </h2>

          {confirmed.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-green-500/8 border border-green-500/20 text-sm font-bold text-green-400">
                ✓ Confirmed findings
                <span className="ml-auto text-xs text-green-400/60 font-medium">{confirmed.length} finding{confirmed.length !== 1 ? "s" : ""}</span>
              </div>
              {confirmed.map((v, i) => <VulnRow key={v.id} vuln={v} index={i} />)}
            </div>
          )}

          {unverified.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-amber-500/8 border border-amber-500/20 text-sm font-bold text-amber-400">
                ⚠ Needs verification
                <span className="ml-auto text-xs text-amber-400/60 font-medium">{unverified.length} finding{unverified.length !== 1 ? "s" : ""}</span>
              </div>
              {unverified.map((v, i) => <VulnRow key={v.id} vuln={v} index={i} needsVerification />)}
            </div>
          )}

          {findings.length === 0 && scanNotes.length === 0 && (
            <div className="text-center py-12 glass-card rounded-xl">
              <Shield className="w-10 h-10 text-green-400 mx-auto mb-3" />
              <h3 className="text-lg font-bold mb-1">No findings from the tests that ran</h3>
              <p className="text-muted-foreground text-sm">
                A clean result says nothing about the areas listed under &ldquo;What this scan tested&rdquo; as not tested.
              </p>
            </div>
          )}

          {findings.length === 0 && scanNotes.length > 0 && (
            <div className="text-center py-12 glass-card rounded-xl">
              <Info className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
              <h3 className="text-lg font-bold mb-1">{NO_FINDINGS_WITH_NOTES.title}</h3>
              <p className="text-muted-foreground text-sm">{NO_FINDINGS_WITH_NOTES.body}</p>
            </div>
          )}

          {scanNotes.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-secondary/40 border border-white/10 text-sm font-bold text-foreground">
                ℹ {SCAN_NOTES_TITLE}
                <span className="ml-auto text-xs text-muted-foreground font-medium">{scanNotesCount(scanNotes.length)}</span>
              </div>
              <p className="text-xs text-muted-foreground px-1">{SCAN_NOTES_BLURB}</p>
              {scanNotes.map((v, i) => <VulnRow key={v.id} vuln={v} index={i} />)}
            </div>
          )}
        </div>

        <div className="space-y-6">
          {aiAnalysis && (
            <div className="glass-card rounded-2xl p-5 border-t-4 border-t-primary">
              <h3 className="text-sm font-bold mb-4 flex items-center gap-2">
                ✦ AI Analysis
              </h3>
              <div className="space-y-4 text-sm">
                <div>
                  <p className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-1.5">Overall Risk</p>
                  <p className="text-foreground/90 leading-relaxed">{aiAnalysis.overallRisk}</p>
                </div>
                {aiAnalysis.topPriorities.length > 0 && (
                  <div>
                    <p className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-1.5">Top Priorities</p>
                    <ul className="space-y-1.5">
                      {aiAnalysis.topPriorities.map((p, i) => (
                        <li key={i} className="flex items-start gap-2 text-foreground/90">
                          <span className="text-primary mt-0.5">•</span> <span>{p}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {aiAnalysis.quickWins.length > 0 && (
                  <div>
                    <p className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-1.5">Quick Wins</p>
                    <ul className="space-y-1.5">
                      {aiAnalysis.quickWins.map((w, i) => (
                        <li key={i} className="flex items-start gap-2 text-foreground/90">
                          <span className="text-green-400 mt-0.5">✓</span> <span>{w}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="glass-card rounded-2xl p-5">
            <h3 className="text-sm font-bold mb-4 flex items-center gap-2 text-muted-foreground uppercase tracking-wider">
              Tech Profile
            </h3>
            <div className="space-y-3">
              {tlsGrade && (
                <div className="flex items-center justify-between text-sm border-b border-white/5 pb-2">
                  <span className="text-muted-foreground flex items-center gap-1.5"><Lock className="w-3.5 h-3.5" /> TLS Grade</span>
                  <span className={cn("font-bold", getGradeColor(tlsGrade))}>{tlsGrade}</span>
                </div>
              )}
              {server && (
                <div className="flex items-center justify-between text-sm border-b border-white/5 pb-2">
                  <span className="text-muted-foreground">Server</span>
                  <span className="font-medium text-xs">{server}</span>
                </div>
              )}
              {technologies.length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground mb-2">Detected Technologies</p>
                  <div className="flex flex-wrap gap-1.5">
                    {technologies.map((t, i) => (
                      <span key={i} className="px-2 py-0.5 bg-secondary text-xs rounded border border-white/5">{t}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Compliance mapping — full width below the grid; the control lists need
          the room. Renders nothing when no findings map to a framework. */}
      <div className="mt-10 space-y-8">
        <SourceCodeCard tests={data.tests ?? null} vulnerabilities={vulnerabilities} />
        <CoverageCard tests={data.tests ?? null} />
        <WithheldCard
          withheld={(data as { withheld?: unknown }).withheld}
          interception={(data as { interception?: Interception | null }).interception ?? null}
        />
        <ComplianceCard compliance={compliance} />
      </div>

      <div className="mt-16 pt-8 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="text-center sm:text-left">
          {foot.prepared && <p className="text-sm font-semibold">{foot.prepared}</p>}
          {foot.showSecScanCredit && (
            <p className="text-xs text-muted-foreground">
              This report was generated by{" "}
              <a href="/" className="text-primary hover:underline font-semibold">SecScan</a>
              {" "}— black-box security scanning for web applications.
            </p>
          )}
          <p className="text-xs text-muted-foreground/50 mt-1">Scanned {dateStr} · {summary.totalVulnerabilities} finding{summary.totalVulnerabilities !== 1 ? "s" : ""}</p>
        </div>
        {foot.showScanCta && (
          <Link
            href="/"
            className="shrink-0 inline-flex items-center gap-2 px-5 py-2.5 bg-primary/10 border border-primary/30 text-primary rounded-xl text-sm font-semibold hover:bg-primary/20 transition-colors"
          >
            <Shield className="w-4 h-4" /> Scan your own site
          </Link>
        )}
      </div>

      {showPdfContainer && (
        <div
          ref={pdfContainerRef}
          style={{
            position: "fixed",
            left: "-9999px",
            top: 0,
            width: "794px",
            backgroundColor: "#09090b",
            zIndex: -1,
            pointerEvents: "none",
          }}
        >
          {/* Same document as the owner's PDF: the app's own dark look. */}
          <PdfReport
            targetUrl={report.targetUrl}
            scannedAt={report.scannedAt}
            summary={summary}
            confirmedVulns={confirmed}
            unverifiedVulns={unverified}
            scanNotes={scanNotes}
            technologies={technologies}
            server={server ?? null}
            tlsGrade={tlsGrade ?? null}
            aiAnalysis={aiAnalysis ?? null}
            compliance={compliance ?? null}
            tests={data.tests ?? null}
            withheld={(data as { withheld?: unknown }).withheld}
            interception={(data as { interception?: Interception | null }).interception ?? null}
            brand={brand}
          />
        </div>
      )}
    </div>
  );
}
