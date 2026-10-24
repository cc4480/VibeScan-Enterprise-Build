import { CheckCircle2, Globe, Info, Search, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { chunkPrompt } from "@/lib/promptChunks";
import { APP_ORIGIN } from "@/lib/origin";
import type { Brand } from "@/lib/branding";
import { NO_FINDINGS_WITH_NOTES, SCAN_NOTES_BLURB, SCAN_NOTES_TITLE } from "@/lib/scan-notes";
import { ComplianceCard, SeverityLegend, type CoverageTest, type SharedReportData } from "@/pages/shared-report-components";
import { Finding, Owasp, Coverage, PdfGrade } from "./pdf-report-sections";
import { WithheldCard, type Interception } from "@/pages/report-viewer-provenance";

/**
 * The report as a PDF: the app's own dark look, laid out for a fixed 794px page width.
 *
 * It renders the app's components (grade ring, coverage card, compliance card, severity
 * colours) in the app's theme rather than a separate white "print" design, so the download
 * reads as the same report. It is drawn off-screen and photographed by html2canvas-pro
 * (lib/pdfExport.ts). Every section carries `data-pdf-block`, which is what lets the exporter
 * end a page between two sections instead of through one.
 *
 * Nothing here is responsive (`md:` classes follow the browser window, not this 794px box).
 */

export interface PdfVuln {
  id: string;
  name: string;
  severity: string;
  category: string;
  description: string;
  solution: string;
  evidence?: string | null;
  cweId?: string | null;
  cvssScore?: number | null;
  wstgId?: string | null;
}

export interface PdfReportData {
  targetUrl: string;
  scannedAt: string | Date;
  summary: {
    grade: string;
    riskScore: number;
    executiveSummary: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    totalVulnerabilities: number;
  };
  confirmedVulns: PdfVuln[];
  unverifiedVulns: PdfVuln[];
  /** The scan's notes about itself, which are not findings (see lib/scan-notes.ts). */
  scanNotes?: PdfVuln[];
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: {
    overallRisk: string;
    topPriorities: string[];
    quickWins: string[];
    complianceNotes?: string | null;
    /** The prompt written for the user's AI editor; the app shows it as "Fix with your AI agent". */
    agentFixPrompt?: string | null;
    source?: "ai" | "template";
  } | null;
  compliance?: SharedReportData["data"]["compliance"];
  pagesScanned?: string[];
  tests?: CoverageTest[] | null;
  /** Findings the scan produced and did not report, with the reason. */
  withheld?: unknown;
  interception?: Interception | null;
  /** Who prepared the report, for an account with report branding (lib/branding.ts). */
  brand?: Brand | null;
}
const PAGES_LIMIT = 25;

/**
 * Cards in the PDF are solid. The app's glass-card is translucent with a backdrop blur, which
 * html2canvas cannot draw: the borders came out as pale outlines and the fill as grey.
 * Scoped to the PDF container, so the on-screen app is unchanged; it also reaches cards inside
 * shared components (ComplianceCard).
 */
const PDF_CSS = `
.pdf-root .glass-card {
  background: #121216 !important;
  border: 1px solid #27272a !important;
  box-shadow: none !important;
  backdrop-filter: none !important;
  -webkit-backdrop-filter: none !important;
}
`;

export function PdfReport(d: PdfReportData) {
  const dateStr = new Date(d.scannedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  const s = d.summary;
  const counts = { critical: s.critical, high: s.high, medium: s.medium, low: s.low, info: s.info };
  const everything = [...d.confirmedVulns, ...d.unverifiedVulns];
  const scanNotes = d.scanNotes ?? [];
  const pages = Array.from(new Set(d.pagesScanned ?? []));

  return (
    <div className="pdf-root text-foreground font-sans" style={{ width: 794, padding: 32, boxSizing: "border-box", background: "#09090b" }}>
      <style>{PDF_CSS}</style>
      {/* Cover */}
      <div data-pdf-block className="glass-card rounded-3xl p-8 mb-6 flex items-center gap-8">
        <PdfGrade grade={s.grade} score={s.riskScore} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary border border-white/5 text-xs font-medium text-muted-foreground">
              <Globe className="w-3.5 h-3.5" /> {d.targetUrl}
            </span>
            {d.pagesScanned != null && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-sky-500/10 border border-sky-500/20 text-xs font-medium text-sky-400/80">
                <Search className="w-3 h-3" /> Scanned {pages.length + 1} page{pages.length + 1 === 1 ? "" : "s"}
              </span>
            )}
          </div>
          {d.brand && <p className="text-xs font-semibold uppercase tracking-wider text-primary mb-2">Prepared by {d.brand.name}</p>}
          <h1 className="text-3xl font-bold tracking-tight mb-3">Security Report</h1>
          <p className="text-sm text-muted-foreground/90 leading-relaxed mb-4">{s.executiveSummary}</p>
          <SeverityLegend counts={counts} />
          <p className="text-[11px] text-muted-foreground/60 mt-4">Scanned {dateStr}{d.tlsGrade ? `  ·  TLS grade ${d.tlsGrade}` : ""}</p>
        </div>
      </div>

      {/* What was tested, and what was not: a PDF is what gets forwarded, so it carries this. */}
      <Coverage tests={d.tests} part="summary" />

      <Owasp vulns={everything} tests={d.tests} />

      <Coverage tests={d.tests} part="list" />

      {/* What the scan found and did not report, and why: a forwarded PDF must not hide it. */}
      {(d.interception || (Array.isArray(d.withheld) && d.withheld.length > 0)) && (
        <div data-pdf-block className="mb-6">
          <WithheldCard withheld={d.withheld} interception={d.interception} />
        </div>
      )}

      {/* Findings. The section heading rides inside the first card's block so it can never be left alone at the foot of a page. */}
      {d.confirmedVulns.length === 0 && d.unverifiedVulns.length === 0 && scanNotes.length === 0 && (
        <div data-pdf-block className="glass-card rounded-2xl p-6 mb-6 text-center">
          <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-2" />
          <h3 className="text-base font-bold mb-1">No findings from the tests that ran</h3>
          <p className="text-xs text-muted-foreground">
            A clean result says nothing about the areas listed under &ldquo;What this scan tested&rdquo; as not tested.
          </p>
        </div>
      )}
      {d.confirmedVulns.length === 0 && d.unverifiedVulns.length === 0 && scanNotes.length > 0 && (
        <div data-pdf-block className="glass-card rounded-2xl p-6 mb-6 text-center">
          <Info className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
          <h3 className="text-base font-bold mb-1">{NO_FINDINGS_WITH_NOTES.title}</h3>
          <p className="text-xs text-muted-foreground">{NO_FINDINGS_WITH_NOTES.body}</p>
        </div>
      )}
      {d.confirmedVulns.map((v, i) => (
        <Finding
          key={v.id}
          v={v}
          index={i + 1}
          heading={i === 0 ? <h2 className="text-lg font-bold mb-3 mt-2">Findings ({d.confirmedVulns.length})</h2> : undefined}
        />
      ))}
      {d.unverifiedVulns.map((v, i) => (
        <Finding
          key={v.id}
          v={v}
          index={i + 1}
          heading={
            i === 0 ? (
              <div className="mb-3 mt-4">
                <h2 className="text-lg font-bold text-amber-400">Needs verification ({d.unverifiedVulns.length})</h2>
                <p className="text-xs text-muted-foreground mt-1">
                  These findings were detected with heuristics. Verify manually before prioritising remediation.
                </p>
              </div>
            ) : undefined
          }
        />
      ))}

      {scanNotes.map((v, i) => (
        <Finding
          key={v.id}
          v={v}
          index={i + 1}
          heading={
            i === 0 ? (
              <div className="mb-3 mt-4">
                <h2 className="text-lg font-bold">{SCAN_NOTES_TITLE} ({scanNotes.length})</h2>
                <p className="text-xs text-muted-foreground mt-1">{SCAN_NOTES_BLURB}</p>
              </div>
            ) : undefined
          }
        />
      ))}

      {d.aiAnalysis && (
        <div data-pdf-block className="glass-card rounded-2xl p-6 mb-6 mt-2">
          <h3 className="text-lg font-bold mb-3">AI Analysis</h3>
          <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider mb-1">Overall risk</p>
          <p className="text-sm leading-relaxed mb-4">{d.aiAnalysis.overallRisk}</p>
          {(d.aiAnalysis.topPriorities?.length ?? 0) > 0 && (
            <>
              <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider mb-1">Top priorities</p>
              <ol className="list-decimal list-inside space-y-1 text-sm mb-4">
                {d.aiAnalysis.topPriorities.map((p, i) => <li key={i}>{p}</li>)}
              </ol>
            </>
          )}
          {(d.aiAnalysis.quickWins?.length ?? 0) > 0 && (
            <>
              <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider mb-1">Quick wins</p>
              <ul className="space-y-1 text-sm">
                {d.aiAnalysis.quickWins.map((w, i) => <li key={i}>✓ {w}</li>)}
              </ul>
            </>
          )}
        </div>
      )}

      {/* The AI fix prompt, as the app shows it. Split at paragraph breaks so a page can end between
          paragraphs; the pieces butt together and read as one card. */}
      {d.aiAnalysis?.agentFixPrompt &&
        (() => {
          const pieces = chunkPrompt(d.aiAnalysis.agentFixPrompt);
          return pieces.map((piece, i) => {
            const first = i === 0;
            const last = i === pieces.length - 1;
            return (
              <div
                key={i}
                data-pdf-block
                className={cn(
                  "glass-card p-5",
                  first ? "border-t-4 border-t-violet-500 rounded-t-2xl" : "border-t-0 rounded-t-none",
                  last ? "rounded-b-2xl mb-6" : "rounded-b-none",
                )}
              >
                {first && (
                  <div className="mb-3">
                    <h3 className="text-lg font-bold flex items-center gap-2">
                      <Terminal className="w-5 h-5 text-violet-400" /> Fix with your AI agent
                    </h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      Paste this into your AI editor (Claude Code, Cursor, Lovable, Bolt). It is written for the code behind this site.
                    </p>
                  </div>
                )}
                <pre className="text-[10.5px] font-mono whitespace-pre-wrap break-words text-foreground/90 leading-relaxed">{piece}</pre>
              </div>
            );
          });
        })()}

      {d.compliance && d.compliance.frameworks.length > 0 && (
        <div data-pdf-block className="mb-6">
          <ComplianceCard compliance={d.compliance} />
        </div>
      )}

      <div data-pdf-block className="glass-card rounded-2xl p-6 mb-2">
        <h3 className="text-sm font-bold text-muted-foreground uppercase tracking-wider mb-3">Tech profile</h3>
        <div className="space-y-1 text-sm">
          {d.tlsGrade && <p><span className="text-muted-foreground">TLS grade:</span> {d.tlsGrade}</p>}
          {d.server && <p><span className="text-muted-foreground">Server:</span> {d.server}</p>}
          {d.technologies.length > 0 && <p><span className="text-muted-foreground">Technologies:</span> {d.technologies.join(", ")}</p>}
        </div>
        {pages.length > 0 && (
          <>
            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider mt-4 mb-1">Pages scanned ({pages.length + 1})</p>
            <div className="text-[10px] font-mono text-muted-foreground space-y-0.5">
              <p className="break-all">{d.targetUrl} (root)</p>
              {pages.slice(0, PAGES_LIMIT).map((u) => <p key={u} className="break-all">{u}</p>)}
              {pages.length > PAGES_LIMIT && <p>… and {pages.length - PAGES_LIMIT} more</p>}
            </div>
          </>
        )}
        <p className="text-[10px] text-muted-foreground/50 mt-4">
          {d.brand ? `Prepared by ${d.brand.name}${d.brand.poweredBy ? " · generated by SecScan" : ""}` : `Generated by SecScan · ${APP_ORIGIN}`}
        </p>
      </div>
    </div>
  );
}