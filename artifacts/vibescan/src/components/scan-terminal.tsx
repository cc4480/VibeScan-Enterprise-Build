import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import { FAMILIES, categoryHex } from "@/lib/category-colors";
import { rowColor, tally, toCheckRow, toRow, type LiveTest, type TerminalItem } from "@/lib/scan-terminal";

interface ScanTerminalProps {
  domain: string;
  sessionId: string;
  status: string;
  error?: string | null;
  /** The lines to show so far (already paced): tests, each followed by its checks. */
  shown: TerminalItem[];
  /** Every test the scanner has finished, shown or not: for the closing tally. */
  all: LiveTest[];
  totalChecks: number;
  caughtUp: boolean;
  progress: number;
  /** owner/repo, for a scan of a repository alone: there is no site, so no site totals or wording. */
  repository?: string | null;
  /** owner/repo a website scan also reads (a repository connected to the scan): its steps are shown as the repository scan shows them. */
  sourceRepository?: string | null;
}

const RULE = "─".repeat(52);

/** The closing line of a repository scan, from its own steps only (the roll-up record repeats the checks' findings). */
function repoSummary(all: LiveTest[]): string {
  const steps = all.filter((x) => x.group === "repository");
  const ran = steps.filter((x) => x.status === "ran").length;
  const empty = steps.filter((x) => x.status === "skipped").length;
  const found = steps.reduce((n, x) => n + x.findings, 0);
  return `✓ ${ran} ${ran === 1 ? "step" : "steps"} run${empty > 0 ? `, ${empty} had nothing to check` : ""}, ${found} ${found === 1 ? "finding" : "findings"}`;
}
const clock = () => new Date().toLocaleTimeString("en-US", { hour12: false });

const STATUS_WORD: Record<string, string> = {
  queued: "waiting",
  paid: "waiting",
  pending: "waiting",
  scanning: "scanning",
  analyzing: "writing report",
  complete: "done",
  failed: "failed",
};

const Cursor = () => (
  <span className="inline-block w-2 h-[1em] ml-1 bg-primary align-middle" style={{ animation: "blink 1.1s step-end infinite" }} />
);

/** The scan terminal. Every line is real; see lib/scan-terminal.ts. */
export function ScanTerminal({ domain, sessionId, status, error, shown, all, totalChecks: siteChecks, caughtUp, progress, repository, sourceRepository }: ScanTerminalProps) {
  // A repository alone is not counted against the website catalogue of checks.
  const totalChecks = repository ? 0 : siteChecks;
  const body = useRef<HTMLDivElement>(null);
  const stamps = useRef<string[]>([]);
  const waiting = ["queued", "paid", "pending"].includes(status);
  const complete = status === "complete";
  const failed = status === "failed";
  const running = !waiting && !complete && !failed;

  // A line's time is when it appeared on screen.
  while (stamps.current.length < shown.length) stamps.current.push(clock());

  useEffect(() => {
    if (body.current) body.current.scrollTop = body.current.scrollHeight;
  }, [shown.length, status]);

  const t = tally(all, totalChecks);
  const checksShown = shown.filter((i) => i.kind === "check").length;
  let previousTest: LiveTest | null = null;

  return (
    <div className="mb-4">
      <div className="rounded-2xl overflow-hidden border border-white/10 shadow-2xl shadow-black/50">
        <div className="bg-[#1e1e1e] border-b border-white/[0.06] px-4 py-3 flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/80" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <span className="w-3 h-3 rounded-full bg-green-500/80" />
          </div>
          <span className="flex-1 text-center text-xs font-mono text-zinc-500 tracking-wide truncate">
            {repository ? `secscan — repository scan — ${repository}` : `secscan — security terminal${domain ? ` — ${domain}` : ""}`}
          </span>
          <div className="flex items-center gap-1.5">
            <span className={cn("w-2 h-2 rounded-full", complete ? "bg-green-500" : failed ? "bg-red-500" : "bg-primary animate-pulse")} />
            <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">{STATUS_WORD[status] ?? status}</span>
          </div>
        </div>

        <div
          ref={body}
          className="bg-[#0d1117] font-mono text-[13px] sm:text-sm leading-relaxed h-[min(64vh,680px)] min-h-[380px] overflow-y-auto px-4 sm:px-6 py-5"
          style={{ scrollbarWidth: "thin", scrollbarColor: "#30363d transparent" }}
        >
          <div className="text-primary/70">SecScan Security Scanner</div>
          <div className="text-zinc-600">{RULE}</div>
          <div className="text-zinc-400">Target  : {repository ? `https://github.com/${repository}` : `https://${domain || "…"}`}</div>
          {sourceRepository && <div className="text-zinc-400">Repository: https://github.com/{sourceRepository}</div>}
          <div className="text-zinc-400">Session : {sessionId}</div>
          {totalChecks > 0 && <div className="text-zinc-400">Checks  : {totalChecks}{complete && caughtUp ? ` across ${t.tests} tests` : ""}</div>}
          <div className="text-zinc-500">{repository ? "Reads every text file in the repository, then runs five checks over what it read." : "A test is one thing the scanner runs; a check is one detection inside it."}</div>
          <div className="text-zinc-500">Every line is a real result, in the colour of its kind of check.</div>
          <div className="text-zinc-600 mb-3">{RULE}</div>

          {waiting && <div className="text-zinc-500">Waiting for an available worker slot…</div>}

          {shown.map((item, i) => {
            if (item.kind === "check") {
              const row = toCheckRow(item.check);
              return (
                <div key={`c:${item.test.name}:${item.check.name}`} className="flex gap-2 py-[1px] pl-6 sm:pl-[86px]">
                  <span className="shrink-0 w-3 text-center" style={{ color: categoryHex(item.check.category ?? item.test.category) }}>●</span>
                  <span className="flex-1 min-w-0 break-words">
                    <span className="text-zinc-400">{item.check.name}</span>
                    <span className={cn("block sm:inline sm:ml-3 text-[12px]", rowColor[row.tone])}>{row.mark} {row.result}</span>
                  </span>
                </div>
              );
            }

            const row = toRow(item.test);
            const firstSkipped = item.test.status === "skipped" && previousTest?.status !== "skipped";
            previousTest = item.test;
            return (
              <div key={`t:${item.test.group}:${item.test.name}`} className={i > 0 ? "mt-1.5" : undefined}>
                {firstSkipped && <div className="mt-3 mb-1 text-zinc-500">{RULE}<br />Not tested on this scan:</div>}
                <div className="flex gap-3 py-[1px]">
                  <span className="shrink-0 text-zinc-700 select-none w-[62px]">{stamps.current[i]}</span>
                  <span className={cn("shrink-0 w-4 text-center", rowColor[row.tone])}>{row.mark}</span>
                  <span className="flex-1 min-w-0 break-words">
                    <span style={{ color: categoryHex(item.test.category) }}>[{row.group}] </span>
                    <span className="text-zinc-100 font-semibold">{row.name}</span>
                    <span className={cn("block sm:inline sm:ml-3", rowColor[row.tone])}>{row.result}</span>
                  </span>
                </div>
              </div>
            );
          })}

          {running && caughtUp && status === "scanning" && <div className="mt-2 text-zinc-500">Waiting for the remaining tests<Cursor /></div>}
          {running && caughtUp && status === "analyzing" && <div className="mt-2 text-green-400/90">All tests finished. Writing your report<Cursor /></div>}

          {complete && caughtUp && (
            <div className="mt-4 flex flex-col gap-0.5 text-green-400">
              <span className="text-zinc-600">{RULE}</span>
              {repository ? (
                <span>{repoSummary(all)}</span>
              ) : (
                <span>✓ {t.tests} tests, {totalChecks} checks: {t.clear} clear, {t.finding} with findings, {t.checked} checked, {t.notRun} not run{t.unrecorded > 0 ? `, ${t.unrecorded} not recorded` : ""}</span>
              )}
              {sourceRepository && !repository && <span>{repoSummary(all)}</span>}
              {t.failed > 0 && <span className="text-amber-400">{t.failed} {t.failed === 1 ? "test" : "tests"} did not run to completion: see above.</span>}
              <span className="text-zinc-500 text-xs">Opening your report…</span>
            </div>
          )}

          {failed && (
            <div className="mt-4 flex flex-col gap-0.5 text-red-400">
              <span className="text-zinc-600">{RULE}</span>
              <span>[!] Scan failed: {error ?? "Unknown error"}</span>
            </div>
          )}
        </div>

        <div className="bg-[#161b22] border-t border-white/[0.06] px-5 py-3">
          <div className="flex items-center justify-between text-xs font-mono mb-2">
            <span className="text-zinc-500">{repository ? `${shown.filter((i) => i.kind === "test").length} steps shown` : `${checksShown}${totalChecks ? ` of ${totalChecks}` : ""} checks shown`}</span>
            <span className={cn("font-semibold", complete ? "text-green-400" : failed ? "text-red-400" : "text-primary")}>{progress}%</span>
          </div>
          <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
            <div
              className={cn("h-full rounded-full transition-all duration-500 ease-out", complete ? "bg-green-500" : failed ? "bg-red-500" : "bg-primary")}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap justify-center gap-x-4 gap-y-1.5 text-[11px] text-muted-foreground" aria-label="Colour key">
        {Object.values(FAMILIES).map((f) => (
          <span key={f.label} className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: f.hex }} />
            {f.label}
          </span>
        ))}
      </div>
      <style>{`@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }`}</style>
    </div>
  );
}
