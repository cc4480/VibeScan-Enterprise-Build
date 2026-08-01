import { useState, useEffect, useRef } from "react";
import { useRoute, Link } from "wouter";
import { useSeo } from "@/lib/seo";
import {
  Shield, Globe, Lock, Loader2, AlertCircle, Clock,
  Download, Share2,
} from "lucide-react";
import { cn, getGradeColor } from "@/lib/utils";
import {
  GradeRing, VulnRow,
  SEV_COLORS, SEV_ORDER, VERIFICATION_THRESHOLD,
  type SharedReportData,
} from "./shared-report-components";

export default function SharedReport() {
  const [, params] = useRoute("/share/:token");
  const token = params?.token ?? "";

  const [report, setReport] = useState<SharedReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<{ status: number; message: string } | null>(null);

  const seoTitle = report
    ? `Grade ${report.data.summary.grade} — ${(() => { try { return new URL(report.targetUrl).hostname; } catch { return report.targetUrl; } })()} | Seclayer Security Report`
    : "Security Report — Seclayer";
  const seoDescription = report
    ? `Security scan of ${report.targetUrl}: Grade ${report.data.summary.grade}, risk score ${report.data.summary.riskScore}/100, ${report.data.summary.totalVulnerabilities} finding${report.data.summary.totalVulnerabilities !== 1 ? "s" : ""}. Powered by Seclayer.`
    : "View this security scan report powered by Seclayer — black-box penetration testing for web applications.";
  useSeo({ title: seoTitle, description: seoDescription, canonical: `https://seclayer.io/s/${token}` });

  // PDF generation state — must be declared before any conditional returns (Rules of Hooks)
  const pdfContainerRef = useRef<HTMLDivElement>(null);
  const [generatingPdf, setGeneratingPdf] = useState(false);
  const [showPdfContainer, setShowPdfContainer] = useState(false);

  useEffect(() => {
    if (!token) return;
    fetch(`/api/share/${token}`)
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({ error: "Unknown error" }));
          setError({ status: r.status, message: body.error ?? "Failed to load report" });
          return;
        }
        const data = await r.json();
        setReport(data as SharedReportData);
      })
      .catch(() => setError({ status: 500, message: "Network error" }))
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading shared report…</p>
      </div>
    );
  }

  if (error) {
    const isExpired = error.status === 410;
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4 max-w-md mx-auto px-4 text-center">
        <div className="w-16 h-16 rounded-full bg-secondary flex items-center justify-center">
          {isExpired ? (
            <Clock className="w-8 h-8 text-muted-foreground" />
          ) : (
            <AlertCircle className="w-8 h-8 text-muted-foreground" />
          )}
        </div>
        <h1 className="text-2xl font-bold">
          {isExpired ? "Link Expired" : "Report Not Found"}
        </h1>
        <p className="text-muted-foreground leading-relaxed">
          {isExpired
            ? "This share link has expired. Ask the report owner to generate a new link."
            : "This share link is invalid or has been revoked. It may have been deleted by the report owner."}
        </p>
        <Link
          href="/"
          className="mt-2 inline-flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground rounded-lg font-semibold hover:opacity-90 transition-opacity"
        >
          <Shield className="w-4 h-4" /> Run your own scan
        </Link>
      </div>
    );
  }

  if (!report) return null;

  const { data } = report;
  const { summary, vulnerabilities, technologies, server, tlsGrade, aiAnalysis } = data;

  const sorted = [...vulnerabilities].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 99) - (SEV_ORDER[b.severity] ?? 99),
  );
  const confirmed = sorted.filter((v) => (v.confidence ?? 100) >= VERIFICATION_THRESHOLD);
  const unverified = sorted.filter((v) => (v.confidence ?? 100) < VERIFICATION_THRESHOLD);

  const dateStr = new Date(report.scannedAt).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric",
  });

  const handleDownloadPDF = async () => {
    if (generatingPdf) return;
    setGeneratingPdf(true);
    setShowPdfContainer(true);
    await new Promise<void>((r) => setTimeout(r, 300));
    try {
      const container = pdfContainerRef.current;
      if (!container) return;

      const [{ default: html2canvas }, { jsPDF }] = await Promise.all([
        import("html2canvas"),
        import("jspdf"),
      ]);

      const canvas = await html2canvas(container, {
        scale: 1.5,
        useCORS: true,
        logging: false,
        backgroundColor: "#ffffff",
        windowWidth: container.scrollWidth,
        windowHeight: container.scrollHeight,
      });

      const imgData = canvas.toDataURL("image/png");
      const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const pageW = pdf.internal.pageSize.getWidth();
      const pageH = pdf.internal.pageSize.getHeight();
      const imgHeightMm = (canvas.height / canvas.width) * pageW;

      let heightLeft = imgHeightMm;
      let yOffset = 0;
      pdf.addImage(imgData, "PNG", 0, yOffset, pageW, imgHeightMm);
      heightLeft -= pageH;

      while (heightLeft > 0) {
        yOffset -= pageH;
        pdf.addPage();
        pdf.addImage(imgData, "PNG", 0, yOffset, pageW, imgHeightMm);
        heightLeft -= pageH;
      }

      let filename = "seclayer-report.pdf";
      try {
        const host = new URL(report.targetUrl).hostname.replace(/^www\./, "");
        filename = `seclayer-${host}.pdf`;
      } catch {
        // keep default
      }
      pdf.save(filename);
    } finally {
      setShowPdfContainer(false);
      setGeneratingPdf(false);
    }
  };

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
        <GradeRing grade={summary.grade} score={summary.riskScore} />
        <div className="flex-1 text-center sm:text-left z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary border border-white/5 text-xs font-medium text-muted-foreground mb-4">
            <Globe className="w-3.5 h-3.5" /> {report.targetUrl}
          </div>
          <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">Security Report</h1>
          <p className="text-base text-muted-foreground/80 leading-relaxed max-w-xl">
            {summary.executiveSummary}
          </p>
          <p className="text-xs text-muted-foreground/50 mt-3">Scanned {dateStr}</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-3 mb-10">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
          const count = summary[sev];
          if (count === 0) return null;
          return (
            <div key={sev} className={cn("px-4 py-2 rounded-lg border flex items-center gap-2", SEV_COLORS[sev])}>
              <span className="font-bold uppercase text-xs tracking-wider">{sev}</span>
              <span className="w-6 h-6 rounded bg-black/20 flex items-center justify-center text-sm font-bold">{count}</span>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          <h2 className="text-xl font-bold border-b border-white/10 pb-4">
            Identified Vulnerabilities
            <span className="bg-secondary text-foreground text-sm py-1 px-3 rounded-full ml-3">{vulnerabilities.length}</span>
          </h2>

          {confirmed.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-emerald-500/8 border border-emerald-500/20 text-sm font-bold text-emerald-400">
                ✓ Confirmed findings
                <span className="ml-auto text-xs text-emerald-400/60 font-medium">{confirmed.length} finding{confirmed.length !== 1 ? "s" : ""}</span>
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

          {vulnerabilities.length === 0 && (
            <div className="text-center py-12 glass-card rounded-xl">
              <Shield className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <h3 className="text-lg font-bold mb-1">No vulnerabilities found</h3>
              <p className="text-muted-foreground text-sm">This application passed all security checks.</p>
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
                          <span className="text-emerald-400 mt-0.5">✓</span> <span>{w}</span>
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

      <div className="mt-16 pt-8 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="text-center sm:text-left">
          <p className="text-xs text-muted-foreground">
            This report was generated by{" "}
            <a href="/" className="text-primary hover:underline font-semibold">Seclayer</a>
            {" "}— black-box security scanning for web applications.
          </p>
          <p className="text-xs text-muted-foreground/50 mt-1">Scanned {dateStr} · {summary.totalVulnerabilities} finding{summary.totalVulnerabilities !== 1 ? "s" : ""}</p>
        </div>
        <Link
          href="/"
          className="shrink-0 inline-flex items-center gap-2 px-5 py-2.5 bg-primary/10 border border-primary/30 text-primary rounded-xl text-sm font-semibold hover:bg-primary/20 transition-colors"
        >
          <Shield className="w-4 h-4" /> Scan your own site
        </Link>
      </div>

      {showPdfContainer && (
        <div
          ref={pdfContainerRef}
          style={{
            position: "fixed",
            left: "-9999px",
            top: 0,
            width: "794px",
            backgroundColor: "#ffffff",
            color: "#111827",
            zIndex: -1,
            pointerEvents: "none",
            fontFamily: "system-ui, sans-serif",
            fontSize: "13px",
            lineHeight: "1.6",
            padding: "32px",
          }}
        >
          <div style={{ marginBottom: "24px", paddingBottom: "20px", borderBottom: "2px solid #e5e7eb" }}>
            <h1 style={{ fontSize: "24px", fontWeight: "bold", marginBottom: "4px" }}>Security Report</h1>
            <p style={{ color: "#6b7280", marginBottom: "12px" }}>{report.targetUrl}</p>
            <div style={{ display: "flex", gap: "24px", flexWrap: "wrap" }}>
              <span><strong>Grade:</strong> {summary.grade} (Risk {summary.riskScore}/100)</span>
              <span><strong>Findings:</strong> {summary.totalVulnerabilities}</span>
              <span><strong>Scanned:</strong> {dateStr}</span>
              {tlsGrade && <span><strong>TLS:</strong> {tlsGrade}</span>}
            </div>
          </div>

          <div style={{ marginBottom: "20px" }}>
            <h2 style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "8px" }}>Executive Summary</h2>
            <p style={{ color: "#374151" }}>{summary.executiveSummary}</p>
          </div>

          <div style={{ display: "flex", gap: "8px", marginBottom: "24px", flexWrap: "wrap" }}>
            {summary.critical > 0 && <span style={{ padding: "4px 10px", background: "#fef2f2", color: "#991b1b", border: "1px solid #fecaca", borderRadius: "4px" }}>🔴 Critical: {summary.critical}</span>}
            {summary.high > 0 && <span style={{ padding: "4px 10px", background: "#fff7ed", color: "#9a3412", border: "1px solid #fed7aa", borderRadius: "4px" }}>🟠 High: {summary.high}</span>}
            {summary.medium > 0 && <span style={{ padding: "4px 10px", background: "#fefce8", color: "#854d0e", border: "1px solid #fde68a", borderRadius: "4px" }}>🟡 Medium: {summary.medium}</span>}
            {summary.low > 0 && <span style={{ padding: "4px 10px", background: "#eff6ff", color: "#1e40af", border: "1px solid #bfdbfe", borderRadius: "4px" }}>🔵 Low: {summary.low}</span>}
            {summary.info > 0 && <span style={{ padding: "4px 10px", background: "#f9fafb", color: "#374151", border: "1px solid #e5e7eb", borderRadius: "4px" }}>⚪ Info: {summary.info}</span>}
          </div>

          {confirmed.length > 0 && (
            <div style={{ marginBottom: "24px" }}>
              <h2 style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "12px", color: "#065f46" }}>✅ Confirmed Findings ({confirmed.length})</h2>
              {confirmed.map((v, i) => (
                <div key={v.id} style={{ marginBottom: "12px", padding: "12px", border: "1px solid #e5e7eb", borderRadius: "8px", pageBreakInside: "avoid" }}>
                  <div style={{ fontWeight: "bold", marginBottom: "6px" }}>{i + 1}. [{v.severity.toUpperCase()}] {v.name}</div>
                  <div style={{ fontSize: "12px", color: "#6b7280", marginBottom: "6px" }}>{v.category}</div>
                  <div style={{ marginBottom: "6px" }}>{v.description}</div>
                  {v.evidence && <div style={{ background: "#f9fafb", padding: "8px", borderRadius: "4px", fontFamily: "monospace", fontSize: "11px", marginBottom: "6px", whiteSpace: "pre-wrap" }}>{v.evidence}</div>}
                  <div style={{ background: "#f0fdf4", padding: "8px", borderRadius: "4px", color: "#166534" }}><strong>Fix:</strong> {v.solution}</div>
                </div>
              ))}
            </div>
          )}

          {unverified.length > 0 && (
            <div style={{ marginBottom: "24px" }}>
              <h2 style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "12px", color: "#92400e" }}>⚠️ Needs Verification ({unverified.length})</h2>
              {unverified.map((v, i) => (
                <div key={v.id} style={{ marginBottom: "12px", padding: "12px", border: "1px solid #fde68a", borderRadius: "8px", pageBreakInside: "avoid" }}>
                  <div style={{ fontWeight: "bold", marginBottom: "6px" }}>{i + 1}. [{v.severity.toUpperCase()}] {v.name}</div>
                  <div style={{ fontSize: "12px", color: "#6b7280", marginBottom: "6px" }}>{v.category}</div>
                  <div style={{ marginBottom: "6px" }}>{v.description}</div>
                  <div style={{ background: "#fffbeb", padding: "8px", borderRadius: "4px", color: "#78350f" }}><strong>Fix:</strong> {v.solution}</div>
                </div>
              ))}
            </div>
          )}

          {aiAnalysis && (
            <div style={{ marginBottom: "24px", paddingTop: "16px", borderTop: "1px solid #e5e7eb" }}>
              <h2 style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "12px" }}>🤖 AI Analysis</h2>
              <div style={{ marginBottom: "8px" }}><strong>Overall Risk:</strong> {aiAnalysis.overallRisk}</div>
              {aiAnalysis.topPriorities.length > 0 && (
                <div style={{ marginBottom: "8px" }}>
                  <strong>Top Priorities:</strong>
                  <ol style={{ marginTop: "4px", paddingLeft: "20px" }}>
                    {aiAnalysis.topPriorities.map((p, i) => <li key={i}>{p}</li>)}
                  </ol>
                </div>
              )}
              {aiAnalysis.quickWins.length > 0 && (
                <div>
                  <strong>Quick Wins:</strong>
                  <ul style={{ marginTop: "4px", paddingLeft: "20px" }}>
                    {aiAnalysis.quickWins.map((w, i) => <li key={i}>✓ {w}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}

          <div style={{ paddingTop: "16px", borderTop: "1px solid #e5e7eb" }}>
            <h2 style={{ fontSize: "16px", fontWeight: "bold", marginBottom: "8px" }}>🖥️ Tech Profile</h2>
            {tlsGrade && <p><strong>TLS Grade:</strong> {tlsGrade}</p>}
            {server && <p><strong>Server:</strong> {server}</p>}
            {technologies.length > 0 && <p><strong>Technologies:</strong> {technologies.join(", ")}</p>}
          </div>

          <div style={{ marginTop: "32px", paddingTop: "12px", borderTop: "1px solid #e5e7eb", textAlign: "center", color: "#9ca3af", fontSize: "11px" }}>
            Generated by Seclayer — https://seclayer.io | {dateStr}
          </div>
        </div>
      )}
    </div>
  );
}
