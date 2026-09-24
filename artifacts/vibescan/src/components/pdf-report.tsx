import { CheckCircle2, Globe, MinusCircle, Search, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { chunkPrompt } from "@/lib/promptChunks";
import { APP_ORIGIN } from "@/lib/origin";
import { CATEGORY_TO_OWASP, OWASP_CATEGORIES, owaspCoverage } from "@/lib/owaspCoverage";
import {
  ComplianceCard,
  GradeRing,
  SEV_COLORS,
  SeverityLegend,
  type CoverageTest,
  type SharedReportData,
} from "@/pages/shared-report-components";

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
  } | null;
  compliance?: SharedReportData["data"]["compliance"];
  pagesScanned?: string[];
  tests?: CoverageTest[] | null;
}

/** A finding's evidence can be huge; the PDF keeps enough to check it and no more. */
const EVIDENCE_LIMIT = 800;
const EVIDENCE_LINES = 14;
const PAGES_LIMIT = 25;

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n).trimEnd() + " …" : s);
/** Evidence is clipped by characters and by lines, so one verbose response cannot fill a page. */
const clipEvidence = (s: string) => {
  const lines = s.split("\n");
  return clip(lines.length > EVIDENCE_LINES ? lines.slice(0, EVIDENCE_LINES).join("\n") + "\n…" : s, EVIDENCE_LIMIT);
};

function Label({ children }: { children: React.ReactNode }) {
  return <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider mb-1">{children}</p>;
}

function Finding({ v, index, heading }: { v: PdfVuln; index: number; heading?: React.ReactNode }) {
  const sev = SEV_COLORS[v.severity] ?? SEV_COLORS.info;
  const refs = [v.cweId, v.cvssScore != null ? `CVSS ${v.cvssScore.toFixed(1)}` : null, v.wstgId].filter(Boolean).join("  ·  ");
  return (
    <div data-pdf-block className="mb-4">
      {heading}
      <div className="rounded-xl overflow-hidden border border-white/10 bg-secondary/10">
        <div className="p-3.5 flex items-center gap-3">
          <span className={cn("px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider shrink-0 border", sev)}>
            {v.severity}
          </span>
          <span className="font-semibold text-sm text-foreground flex-1">
            {index}. {v.name}
          </span>
          <span className="text-[11px] text-muted-foreground shrink-0">{v.category}</span>
        </div>
        <div className="px-3.5 py-3.5 border-t border-white/5 bg-secondary/20 space-y-3">
          <div>
            <Label>Description</Label>
            <p className="text-xs text-foreground/90 leading-relaxed">{v.description}</p>
          </div>
          {v.evidence && (
            <div>
              <Label>Evidence</Label>
              <div className="bg-background border border-white/10 rounded-lg p-2.5 text-[10px] font-mono text-muted-foreground whitespace-pre-wrap break-all">
                {clipEvidence(v.evidence)}
              </div>
            </div>
          )}
          <div>
            <Label>How to fix</Label>
            <p className="text-xs text-foreground/90 leading-relaxed">{v.solution}</p>
          </div>
          {refs && <p className="text-[10px] text-muted-foreground/70 font-mono">{refs}</p>}
        </div>
      </div>
    </div>
  );
}

const STATE_LABEL = { partial: "partly tested", untested: "not tested", unknown: "no record" } as const;

/** Static OWASP summary. The interactive card uses recharts; a PDF wants plain markup. */
function Owasp({ vulns, tests }: { vulns: PdfVuln[]; tests?: CoverageTest[] | null }) {
  const counts: Record<string, number> = {};
  for (const v of vulns) for (const code of CATEGORY_TO_OWASP[v.category] ?? []) counts[code] = (counts[code] ?? 0) + 1;
  const rows = OWASP_CATEGORIES.map((c) => ({ ...c, ...owaspCoverage(c.code, counts[c.code] ?? 0, tests), count: counts[c.code] ?? 0 }));
  const clear = rows.filter((r) => r.state === "clear").length;
  const flagged = rows.filter((r) => r.state === "flagged").length;
  const notFull = rows.length - clear - flagged;

  return (
    <div data-pdf-block className="glass-card rounded-2xl p-5 mb-6">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-muted-foreground uppercase tracking-wider">OWASP Top 10</h3>
        <div className="flex items-center gap-2 text-[11px]">
          {flagged > 0 && <span className="px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 font-medium">{flagged} flagged</span>}
          <span className="px-2 py-0.5 rounded-full bg-green-500/10 border border-green-500/20 text-green-400 font-medium">{clear} clear</span>
          {notFull > 0 && <span className="px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 font-medium">{notFull} not fully tested</span>}
        </div>
      </div>
      <div className="space-y-0.5">
        {rows.map((r) => (
          <div key={r.code} className="flex items-center gap-3 px-2 py-1">
            <span className="font-mono text-[11px] font-bold text-muted-foreground/60 w-7 shrink-0">{r.code}</span>
            <span className="flex-1 text-xs text-foreground/80">{r.name}</span>
            {r.state === "flagged" ? (
              <span className="text-xs font-bold text-red-400">{r.count} finding{r.count === 1 ? "" : "s"}</span>
            ) : r.state === "clear" ? (
              <span className="flex items-center gap-1 text-[11px] text-green-400/80"><CheckCircle2 className="w-3.5 h-3.5" /> tested, none</span>
            ) : (
              <span className="flex items-center gap-1 text-[11px] text-amber-400/80"><MinusCircle className="w-3.5 h-3.5" /> {STATE_LABEL[r.state as keyof typeof STATE_LABEL]}</span>
            )}
          </div>
        ))}
      </div>
      <p className="mt-3 text-[10px] text-muted-foreground/60 leading-relaxed">
        &ldquo;Tested, none&rdquo; means every test covering the category ran and found nothing; it is not a statement of security.
        Based on OWASP Top 10 2021. A04, A09 and A10 need authenticated or server-side testing and are out of scope for black-box scans.
      </p>
    </div>
  );
}


/**
 * What ran and what did not, for a page that cannot open a <details>. Two parts: the summary
 * (the piece that must not be missed) sits beside the grade, and the full list can follow later.
 */
function Coverage({ tests, part }: { tests?: CoverageTest[] | null; part: "summary" | "list" }) {
  const list = Array.isArray(tests) ? tests.filter((t) => t && typeof t.name === "string") : [];
  if (list.length === 0) {
    if (part === "list") return null;
    return (
      <div data-pdf-block className="glass-card rounded-2xl p-5 mb-6">
        <h3 className="text-base font-bold mb-1">What this scan tested</h3>
        <p className="text-xs text-muted-foreground">
          Not recorded for this scan, which was run before test records were kept. Do not read the grade as a statement
          about full coverage.
        </p>
      </div>
    );
  }
  const ran = list.filter((t) => t.status === "ran").length;
  const notRun = list.filter((t) => t.status !== "ran");
  const skipped = notRun.filter((t) => t.status === "skipped").length;
  const failed = notRun.length - skipped;
  const groups = Array.from(new Set(list.map((t) => t.group)));

  if (part === "list") {
    return (
      <div data-pdf-block className="glass-card rounded-2xl p-5 mb-6">
        <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">All {list.length} tests</h3>
        <div className="grid grid-cols-2 gap-x-6 gap-y-3">
          {groups.map((g) => (
            <div key={g}>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">{g}</p>
              <ul className="space-y-0.5">
                {list.filter((t) => t.group === g).map((t, i) => (
                  <li key={`${t.name}-${i}`} className="text-[11px] flex items-baseline gap-1.5">
                    <span
                      className={cn(
                        "font-mono text-[9px] shrink-0 w-11",
                        t.status === "ran" ? "text-green-400" : t.status === "failed" ? "text-amber-400" : "text-muted-foreground",
                      )}
                    >
                      {t.status}
                    </span>
                    <span className="flex-1 min-w-0 break-words">{t.name}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div data-pdf-block className="glass-card rounded-2xl p-5 mb-6">
      <h3 className="text-base font-bold mb-1">What this scan tested</h3>
      <p className="text-sm text-muted-foreground mb-3">
        <span className="font-semibold text-foreground">{ran} of {list.length} tests ran</span>
        {skipped > 0 && `, ${skipped} skipped`}
        {failed > 0 && `, ${failed} failed`}.
      </p>
      {notRun.length > 0 ? (
        <>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">Not tested on this scan</p>
          <ul className="space-y-1.5 mb-2">
            {notRun.map((t, i) => (
              <li key={`${t.name}-${i}`} className="text-xs flex items-start gap-2">
                <MinusCircle className={cn("w-3.5 h-3.5 mt-0.5 shrink-0", t.status === "failed" ? "text-amber-400" : "text-muted-foreground")} />
                <span className="flex-1">
                  <span className="font-medium">{t.name}</span>
                  <span className="text-muted-foreground">
                    {" — "}
                    {t.status === "failed" ? `failed to run${t.reason ? `: ${t.reason}` : ""}` : (t.reason ?? "skipped")}
                  </span>
                </span>
              </li>
            ))}
          </ul>
          <p className="text-[11px] text-muted-foreground/80">A clean result says nothing about these areas.</p>
        </>
      ) : (
        <p className="text-xs flex items-center gap-2"><CheckCircle2 className="w-4 h-4 text-green-400" /> Every test ran.</p>
      )}
    </div>
  );
}

export function PdfReport(d: PdfReportData) {
  const dateStr = new Date(d.scannedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  const s = d.summary;
  const counts = { critical: s.critical, high: s.high, medium: s.medium, low: s.low, info: s.info };
  const everything = [...d.confirmedVulns, ...d.unverifiedVulns];
  const pages = Array.from(new Set(d.pagesScanned ?? []));

  return (
    <div className="bg-background text-foreground font-sans" style={{ width: 794, padding: 32, boxSizing: "border-box" }}>
      {/* Cover */}
      <div data-pdf-block className="glass-card rounded-3xl p-8 mb-6 flex items-center gap-8">
        <GradeRing grade={s.grade} score={s.riskScore} />
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

      {/* Findings. The section heading rides inside the first card's block so it can never be left alone at the foot of a page. */}
      {d.confirmedVulns.length === 0 && d.unverifiedVulns.length === 0 && (
        <div data-pdf-block className="glass-card rounded-2xl p-6 mb-6 text-center">
          <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-2" />
          <h3 className="text-base font-bold mb-1">No findings from the tests that ran</h3>
          <p className="text-xs text-muted-foreground">
            A clean result says nothing about the areas listed under &ldquo;What this scan tested&rdquo; as not tested.
          </p>
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
        <p className="text-[10px] text-muted-foreground/50 mt-4">Generated by SecScan · {APP_ORIGIN}</p>
      </div>
    </div>
  );
}
