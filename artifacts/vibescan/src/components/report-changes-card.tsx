import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { changeGroups, headline, unchangedSentence, type ScanChanges } from "@/lib/report-changes";

const TONE: Record<string, string> = {
  warn: "bg-amber-500/10 text-amber-300 border-amber-500/25",
  good: "bg-green-500/10 text-green-300 border-green-500/25",
  neutral: "bg-white/5 text-zinc-300 border-white/10",
};
const DOT: Record<string, string> = { critical: "#f87171", high: "#fb923c", medium: "#facc15", low: "#60a5fa", info: "#94a3b8" };

/** "What changed since your last scan": new, fixed, and the ones that could not be re-checked. See lib/report-changes.ts. */
export function ReportChangesCard({ changes }: { changes: ScanChanges }) {
  const groups = changeGroups(changes);
  const [open, setOpen] = useState<string | null>(groups[0]?.key ?? null);
  const nothing = groups.length === 0;

  return (
    <section aria-label="Changes since the last scan" className="glass-panel rounded-2xl p-5 mb-8">
      <h2 className="text-lg font-bold mb-3">{headline(changes)}</h2>

      {nothing ? (
        <p className="text-sm text-muted-foreground">{unchangedSentence(changes)}</p>
      ) : (
        <div className="space-y-2">
          {groups.map((g) => (
            <div key={g.key} className="rounded-xl border border-white/10 overflow-hidden">
              <button
                type="button"
                onClick={() => setOpen(open === g.key ? null : g.key)}
                aria-expanded={open === g.key}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-white/[0.03]"
              >
                <span className={cn("px-2.5 py-0.5 rounded-full text-xs font-bold border", TONE[g.tone])}>{g.label}</span>
                <span className="flex-1 text-xs text-muted-foreground truncate">{g.note}</span>
                <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform shrink-0", open === g.key && "rotate-180")} />
              </button>
              {open === g.key && (
                <ul className="px-4 pb-3 pt-1 space-y-1.5 border-t border-white/5">
                  {g.items.map((item) => (
                    <li key={`${item.category}:${item.name}`} className="flex items-start gap-2 text-sm">
                      <span className="mt-1.5 w-2 h-2 rounded-full shrink-0" style={{ background: DOT[item.severity] ?? DOT["info"] }} />
                      <span>{item.name}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
          {changes.unchanged > 0 && <p className="text-xs text-muted-foreground pt-1">{changes.unchanged} other finding{changes.unchanged === 1 ? "" : "s"} carried over unchanged.</p>}
        </div>
      )}

      {changes.differentAccess && (
        <p className="text-xs text-amber-300/90 mt-3">
          One of these scans used a login and the other did not, so they saw different parts of the site. Read the comparison with that in mind.
        </p>
      )}
    </section>
  );
}
