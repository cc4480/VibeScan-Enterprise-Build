import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import { rowColor, toRow, type LiveTest } from "@/lib/scan-terminal";

interface ScanTerminalProps {
  domain: string;
  sessionId: string;
  status: string;
  error?: string | null;
  /** The tests to show so far (already paced). */
  shown: LiveTest[];
  /** Every test the scanner has finished, shown or not: for the closing tally. */
  all: LiveTest[];
  caughtUp: boolean;
  progress: number;
}

const RULE = "─".repeat(52);
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

/** The scan terminal. Every row is a test the scanner really finished; see lib/scan-terminal.ts. */
export function ScanTerminal({ domain, sessionId, status, error, shown, all, caughtUp, progress }: ScanTerminalProps) {
  const body = useRef<HTMLDivElement>(null);
  const stamps = useRef<string[]>([]);
  const waiting = ["queued", "paid", "pending"].includes(status);
  const complete = status === "complete";
  const failed = status === "failed";
  const running = !waiting && !complete && !failed;

  // A row's time is when it appeared on screen.
  while (stamps.current.length < shown.length) stamps.current.push(clock());

  useEffect(() => {
    if (body.current) body.current.scrollTop = body.current.scrollHeight;
  }, [shown.length, status]);

  const tally = (s: LiveTest["status"]) => all.filter((t) => t.status === s).length;
  const findings = all.filter((t) => t.status === "ran" && t.findings > 0).length;

  return (
    <div className="rounded-2xl overflow-hidden border border-white/10 shadow-2xl shadow-black/50 mb-4">
      <div className="bg-[#1e1e1e] border-b border-white/[0.06] px-4 py-3 flex items-center gap-3">
        <div className="flex gap-1.5">
          <span className="w-3 h-3 rounded-full bg-red-500/80" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <span className="w-3 h-3 rounded-full bg-green-500/80" />
        </div>
        <span className="flex-1 text-center text-xs font-mono text-zinc-500 tracking-wide truncate">
          secscan — security terminal{domain ? ` — ${domain}` : ""}
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
        <div className="text-zinc-400">Target  : https://{domain || "…"}</div>
        <div className="text-zinc-400">Session : {sessionId}</div>
        <div className="text-zinc-500">Each line below is a test that has finished, with its real result.</div>
        <div className="text-zinc-600 mb-3">{RULE}</div>

        {waiting && (
          <div className="text-zinc-500">Waiting for an available worker slot…</div>
        )}

        {shown.map((t, i) => {
          const row = toRow(t);
          const firstSkipped = t.status === "skipped" && shown[i - 1]?.status !== "skipped";
          return (
            <div key={`${t.group}:${t.name}`}>
              {firstSkipped && <div className="mt-3 mb-1 text-zinc-500">{RULE}<br />Not tested on this scan:</div>}
              <div className="flex gap-3 py-[1px]">
              <span className="shrink-0 text-zinc-700 select-none w-[62px]">{stamps.current[i]}</span>
              <span className={cn("shrink-0 w-4 text-center", rowColor[row.tone])}>{row.mark}</span>
              <span className="flex-1 min-w-0 break-words">
                <span className="text-zinc-600">[{row.group}] </span>
                <span className="text-zinc-200">{row.name}</span>
                <span className={cn("block sm:inline sm:ml-3", rowColor[row.tone])}>{row.result}</span>
              </span>
              </div>
            </div>
          );
        })}

        {running && caughtUp && status === "scanning" && (
          <div className="mt-2 text-zinc-500">
            Waiting for the remaining tests
            <span className="inline-block w-2 h-[1em] ml-1 bg-primary align-middle" style={{ animation: "blink 1.1s step-end infinite" }} />
          </div>
        )}
        {running && caughtUp && status === "analyzing" && (
          <div className="mt-2 text-green-400/90">
            All tests finished. Writing your report
            <span className="inline-block w-2 h-[1em] ml-1 bg-primary align-middle" style={{ animation: "blink 1.1s step-end infinite" }} />
          </div>
        )}

        {complete && caughtUp && (
          <div className="mt-4 flex flex-col gap-0.5 text-green-400">
            <span className="text-zinc-600">{RULE}</span>
            <span>
              ✓ {all.length} tests: {tally("ran")} ran, {tally("skipped")} skipped, {tally("failed")} did not run
              {findings > 0 ? `, ${findings} with findings` : ""}
            </span>
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
          <span className="text-zinc-500">{shown.length} of {Math.max(all.length, shown.length)} finished tests shown</span>
          <span className={cn("font-semibold", complete ? "text-green-400" : failed ? "text-red-400" : "text-primary")}>{progress}%</span>
        </div>
        <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
          <div
            className={cn("h-full rounded-full transition-all duration-500 ease-out", complete ? "bg-green-500" : failed ? "bg-red-500" : "bg-primary")}
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>
      <style>{`@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }`}</style>
    </div>
  );
}
