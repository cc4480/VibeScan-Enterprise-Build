/** The building blocks of the PDF report: findings, OWASP table, coverage and the grade badge. */
import { CheckCircle2, MinusCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { OWASP_CATEGORIES, owaspCoverage, owaspFindingCounts } from "@/lib/owaspCoverage";
import { SEV_COLORS, type CoverageTest } from "@/pages/shared-report-components";
import { type PdfVuln } from "./pdf-report";

/** A finding's evidence can be huge; the PDF keeps enough to check it and no more. */
export const EVIDENCE_LIMIT = 800;

export const EVIDENCE_LINES = 14;

export const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n).trimEnd() + " …" : s);

/** Evidence is clipped by characters and by lines, so one verbose response cannot fill a page. */
export const clipEvidence = (s: string) => {
  const lines = s.split("\n");
  return clip(lines.length > EVIDENCE_LINES ? lines.slice(0, EVIDENCE_LINES).join("\n") + "\n…" : s, EVIDENCE_LIMIT);
};

export function Label({ children }: { children: React.ReactNode }) {
  return <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider mb-1">{children}</p>;
}

export function Finding({ v, index, heading }: { v: PdfVuln; index: number; heading?: React.ReactNode }) {
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

export const STATE_LABEL = { partial: "partly tested", untested: "not tested", unknown: "no record" } as const;

/** Static OWASP summary. The interactive card uses recharts; a PDF wants plain markup. */
export function Owasp({ vulns, tests }: { vulns: PdfVuln[]; tests?: CoverageTest[] | null }) {
  const counts = owaspFindingCounts(vulns);
  const rows = OWASP_CATEGORIES.map((c) => {
    const n = counts[c.code] ?? { actionable: 0, info: 0 };
    return { ...c, ...owaspCoverage(c.code, n.actionable, tests), count: n.actionable, info: n.info };
  });
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
            {r.state !== "flagged" && r.info > 0 && (
              <span className="text-[11px] text-zinc-400">· {r.info} info note{r.info === 1 ? "" : "s"}</span>
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
export function Coverage({ tests, part }: { tests?: CoverageTest[] | null; part: "summary" | "list" }) {
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

export const GRADE_HEX: Record<string, string> = { A: "#4ade80", B: "#a3e635", C: "#facc15", D: "#fb923c", F: "#f87171" };

/**
 * The grade for a printed page. The app's GradeRing draws its arc as the risk score, so an A
 * (risk 5) is an almost empty ring: fine on screen beside the number, but on paper it reads as
 * broken. Here the ring is solid in the grade's colour and the risk is written underneath.
 */
export function PdfGrade({ grade, score }: { grade: string; score: number }) {
  const graded = grade in GRADE_HEX;
  const color = graded ? GRADE_HEX[grade]! : "#94a3b8";
  return (
    <div
      className="shrink-0 flex flex-col items-center justify-center rounded-full"
      style={{ width: 132, height: 132, border: `5px solid ${color}`, background: "#0c0c0f" }}
    >
      <span style={{ color, fontSize: 56, fontWeight: 800, lineHeight: 1 }}>{graded ? grade : "—"}</span>
      <span style={{ color: "#a1a1aa", fontSize: 11, fontWeight: 600, letterSpacing: "0.14em", marginTop: 6 }}>
        {graded ? `RISK ${score}/100` : "INCOMPLETE"}
      </span>
    </div>
  );
}
