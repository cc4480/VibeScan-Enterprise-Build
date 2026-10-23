/** What the scan tested and skipped: the coverage card, its print form and Markdown. */
import { AlertTriangle, CheckCircle2, MinusCircle } from "lucide-react";
import { cn } from "@/lib/utils";

export interface CoverageTest {
  group: string;
  name: string;
  status: "ran" | "skipped" | "failed";
  findings: number;
  durationMs: number;
  reason?: string;
  /** Names of the findings this test raised. */
  found?: string[];
  /** For the repository scan: what was read and what each check found (see shared-report-source.tsx). */
  source?: import("./shared-report-source").SourceRecord;
}

export const isCoverageTest = (t: unknown): t is CoverageTest => {
  if (!t || typeof t !== "object") return false;
  const r = t as Record<string, unknown>;
  return typeof r.name === "string" && (r.status === "ran" || r.status === "skipped" || r.status === "failed");
};

/**
 * What the scan tested, and what it did not.
 *
 * A grade reads as "everything was checked". It was not: without verified
 * ownership every active test is skipped, and without a second login access
 * control is. This card says so beside the grade, so a clean result cannot be
 * taken as a statement about areas the scan never looked at. Reports from before
 * test records existed say that instead of implying full coverage.
 */
export function CoverageCard({ tests }: { tests?: CoverageTest[] | null }) {
  const list = Array.isArray(tests) ? tests.filter(isCoverageTest) : [];

  if (list.length === 0) {
    return (
      <div className="glass-card rounded-2xl p-6">
        <h3 className="text-lg font-bold mb-1">What this scan tested</h3>
        <p className="text-sm text-muted-foreground">
          Not recorded for this scan, which was run before test records were kept. Do not read the grade as a
          statement about full coverage.
        </p>
      </div>
    );
  }

  const ran = list.filter((t) => t.status === "ran");
  const skipped = list.filter((t) => t.status === "skipped");
  const failed = list.filter((t) => t.status === "failed");
  const notRun = list.filter((t) => t.status !== "ran");
  const groups = Array.from(new Set(list.map((t) => t.group)));

  return (
    <div className="glass-card rounded-2xl p-6">
      <h3 className="text-lg font-bold mb-1">What this scan tested</h3>
      <p className="text-sm text-muted-foreground mb-4">
        <span className="font-semibold text-foreground">
          {ran.length} of {list.length} tests ran
        </span>
        {skipped.length > 0 && `, ${skipped.length} skipped`}
        {failed.length > 0 && `, ${failed.length} failed`}.
      </p>

      {notRun.length > 0 ? (
        <>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
            Not tested on this scan
          </p>
          <ul className="space-y-2 mb-3">
            {notRun.map((t, i) => (
              <li key={`${t.name}-${i}`} className="text-sm flex items-start gap-2">
                {t.status === "failed" ? (
                  <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-amber-400" />
                ) : (
                  <MinusCircle className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
                )}
                <span className="flex-1">
                  <span className="font-medium">{t.name}</span>
                  <span className="block text-xs text-muted-foreground">
                    {t.status === "failed" ? `Failed to run${t.reason ? `: ${t.reason}` : ""}` : (t.reason ?? "Skipped")}
                  </span>
                </span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground/80 leading-relaxed">
            A clean result says nothing about these areas.
          </p>
        </>
      ) : (
        <p className="text-sm flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-green-400" /> Every test ran.
        </p>
      )}

      <details className="mt-4 group">
        <summary className="cursor-pointer text-xs text-primary hover:underline">All {list.length} tests</summary>
        <div className="mt-3 space-y-3">
          {groups.map((g) => (
            <div key={g}>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">{g}</p>
              <ul className="space-y-1">
                {list
                  .filter((t) => t.group === g)
                  .map((t, i) => (
                    <li key={`${t.name}-${i}`} className="text-xs flex items-baseline gap-2">
                      <span
                        className={cn(
                          "font-mono text-[10px] shrink-0 w-14",
                          t.status === "ran" ? "text-green-400" : t.status === "failed" ? "text-amber-400" : "text-muted-foreground",
                        )}
                      >
                        {t.status}
                      </span>
                      <span className="flex-1 min-w-0 break-words">{t.name}</span>
                      {t.status === "ran" && (
                        <span className="text-muted-foreground shrink-0">
                          {t.findings} finding{t.findings === 1 ? "" : "s"}
                        </span>
                      )}
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}

/**
 * Print and PDF version of the coverage card: plain, light-on-white, no <details>,
 * because a PDF cannot expand anything. A downloaded report is what gets forwarded
 * to a client or a manager, so it must carry what was NOT tested with it.
 */
export function PrintCoverage({ tests }: { tests?: CoverageTest[] | null }) {
  const list = Array.isArray(tests) ? tests.filter(isCoverageTest) : [];
  const heading = <h2 className="text-lg font-bold mb-2 text-gray-900">What this scan tested</h2>;

  if (list.length === 0) {
    return (
      <div className="mb-8 pt-6 border-t-2 border-gray-200">
        {heading}
        <p className="text-gray-700">
          Not recorded for this scan, which was run before test records were kept. Do not read the grade as a
          statement about full coverage.
        </p>
      </div>
    );
  }

  const ran = list.filter((t) => t.status === "ran").length;
  const notRun = list.filter((t) => t.status !== "ran");
  const skipped = notRun.filter((t) => t.status === "skipped").length;
  const failed = notRun.length - skipped;

  return (
    <div className="mb-8 pt-6 border-t-2 border-gray-200">
      {heading}
      <p className="text-gray-700 mb-2">
        <strong>{ran} of {list.length} tests ran</strong>
        {skipped > 0 && `, ${skipped} skipped`}
        {failed > 0 && `, ${failed} failed`}.
      </p>
      {notRun.length > 0 ? (
        <>
          <p className="text-sm font-semibold text-gray-800 mb-1">Not tested on this scan</p>
          <ul className="space-y-1 mb-2">
            {notRun.map((t, i) => (
              <li key={`${t.name}-${i}`} className="text-gray-700 text-sm">
                <strong>{t.name}</strong>
                <span className="text-gray-500">
                  {" — "}
                  {t.status === "failed" ? `failed to run${t.reason ? `: ${t.reason}` : ""}` : (t.reason ?? "skipped")}
                </span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-gray-500">A clean result says nothing about these areas.</p>
        </>
      ) : (
        <p className="text-gray-700 text-sm">Every test ran.</p>
      )}
    </div>
  );
}

/** The same content as markdown lines, for the "Copy report" text an AI editor reads. */
export function coverageMarkdown(tests?: CoverageTest[] | null): string[] {
  const list = Array.isArray(tests) ? tests.filter(isCoverageTest) : [];
  if (list.length === 0) {
    return [
      "## What this scan tested",
      "",
      "Not recorded for this scan (it predates test records). Do not read the grade as a statement about full coverage.",
      "",
    ];
  }
  const ran = list.filter((t) => t.status === "ran").length;
  const notRun = list.filter((t) => t.status !== "ran");
  const skipped = notRun.filter((t) => t.status === "skipped").length;
  const failed = notRun.length - skipped;
  const out = [
    "## What this scan tested",
    "",
    `${ran} of ${list.length} tests ran${skipped > 0 ? `, ${skipped} skipped` : ""}${failed > 0 ? `, ${failed} failed` : ""}.`,
    "",
  ];
  if (notRun.length > 0) {
    out.push("Not tested on this scan — a clean result says nothing about these:", "");
    for (const t of notRun) {
      out.push(`- ${t.name}: ${t.status === "failed" ? `failed to run${t.reason ? ` — ${t.reason}` : ""}` : (t.reason ?? "skipped")}`);
    }
    out.push("");
  } else {
    out.push("Every test ran.", "");
  }
  return out;
}
