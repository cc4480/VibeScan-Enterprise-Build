/** Transparency: how each finding was found, and what the scan withheld and why. */
import { createContext, useContext } from "react";
import { EyeOff, ShieldAlert } from "lucide-react";
import { findingProvenance, confidenceText, ACTIVE_NO_REQUESTS_TEXT, PROVENANCE_KIND_TEXT, type ProvenanceTest } from "@/lib/provenance";

/** The report's test records, so every finding card can name the check that raised it. */
export const ReportTestsContext = createContext<ProvenanceTest[] | null>(null);

export interface WithheldFinding {
  name: string;
  severity: string;
  category: string;
  reason: string;
}

export interface Interception {
  kind: "bot challenge" | "sign-in wall" | "app not running";
  vendor: string | null;
  signal: string;
}

export const isWithheld = (w: unknown): w is WithheldFinding => {
  if (!w || typeof w !== "object") return false;
  const r = w as Record<string, unknown>;
  return typeof r.name === "string" && typeof r.reason === "string";
};

/** "How this was found" inside an expanded finding. */
export function FindingProvenance({ vuln }: { vuln: { name: string; category: string; evidence?: string | null; confidence?: number | null } }) {
  const tests = useContext(ReportTestsContext);
  const p = findingProvenance(vuln, tests);
  const confidence = confidenceText(vuln.confidence);
  return (
    <div>
      <h5 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">How this was found</h5>
      <div className="bg-background border border-white/10 rounded-lg p-3 text-xs text-muted-foreground space-y-1.5">
        {p.check && (
          <p>
            Check: <span className="text-foreground/90 font-medium">{p.check}</span>
          </p>
        )}
        <p>{PROVENANCE_KIND_TEXT[p.kind]}</p>
        {p.kind === "active" && p.requests.length === 0 && <p>{ACTIVE_NO_REQUESTS_TEXT}</p>}
        {p.requests.length > 0 && (
          <div>
            <p className="mb-1">Requests the scanner made:</p>
            <ul className="font-mono space-y-0.5 break-all">
              {p.requests.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        )}
        {confidence && <p>{confidence}</p>}
      </div>
    </div>
  );
}

const INTERCEPTION_TITLE: Record<Interception["kind"], string> = {
  "bot challenge": "A bot-protection page answered instead of your site",
  "sign-in wall": "A sign-in page answered instead of your app",
  "app not running": "The hosting platform answered instead of your app",
};

/**
 * What the scan found and chose not to report, with the reason. A scanner that drops findings out of
 * sight asks to be trusted; this one shows its work, including the parts it threw away.
 */
export function WithheldCard({ withheld, interception }: { withheld?: unknown; interception?: Interception | null }) {
  const list = Array.isArray(withheld) ? withheld.filter(isWithheld) : [];
  if (list.length === 0 && !interception) return null;
  return (
    <div className="glass-card rounded-2xl p-6">
      <h3 className="text-lg font-bold mb-1 flex items-center gap-2">
        <EyeOff className="w-4 h-4 text-muted-foreground" /> Withheld from this report
      </h3>
      {interception && (
        <div className="mt-2 mb-3 flex gap-2 p-3 rounded-lg bg-amber-500/8 border border-amber-500/25">
          <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs">
            <p className="font-semibold text-amber-300">
              {INTERCEPTION_TITLE[interception.kind]}
              {interception.vendor ? ` (${interception.vendor})` : ""}
            </p>
            <p className="text-amber-200/70 mt-0.5 break-all">{interception.signal}</p>
          </div>
        </div>
      )}
      <p className="text-sm text-muted-foreground mb-3">
        {list.length > 0
          ? `The scan produced ${list.length} finding${list.length === 1 ? "" : "s"} it did not report, because ${list.length === 1 ? "it was" : "they were"} not about your site or ${list.length === 1 ? "was" : "were"} covered by a stronger test. Listed so nothing is dropped out of sight.`
          : "Nothing that reads the page was reported, because what answered was not your app."}
      </p>
      {list.length > 0 && (
        <ul className="space-y-2">
          {list.map((w, i) => (
            <li key={`${w.name}-${i}`} className="text-sm">
              <span className="font-medium">{w.name}</span>
              <span className="text-xs text-muted-foreground"> · {w.severity}</span>
              <span className="block text-xs text-muted-foreground">{w.reason}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Print (Ctrl+P) version: light-on-white, like PrintCoverage. */
export function PrintWithheld({ withheld, interception }: { withheld?: unknown; interception?: Interception | null }) {
  const list = Array.isArray(withheld) ? withheld.filter(isWithheld) : [];
  if (list.length === 0 && !interception) return null;
  return (
    <div className="mb-8 pt-6 border-t-2 border-gray-200">
      <h2 className="text-lg font-bold mb-2 text-gray-900">Withheld from this report</h2>
      {interception && (
        <p className="text-gray-700 mb-2">
          <strong>
            {INTERCEPTION_TITLE[interception.kind]}
            {interception.vendor ? ` (${interception.vendor})` : ""}
          </strong>
          <span className="block text-xs text-gray-500 break-all">{interception.signal}</span>
        </p>
      )}
      {list.length > 0 ? (
        <ul className="space-y-1">
          {list.map((w, i) => (
            <li key={`${w.name}-${i}`} className="text-gray-700 text-sm">
              <strong>{w.name}</strong> <span className="text-gray-500">({w.severity}) {w.reason}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-gray-700 text-sm">Nothing that reads the page was reported, because what answered was not your app.</p>
      )}
    </div>
  );
}

/** Plain-text form for the Markdown copy. */
export function withheldMarkdown(withheld?: unknown, interception?: Interception | null): string[] {
  const list = Array.isArray(withheld) ? withheld.filter(isWithheld) : [];
  if (list.length === 0 && !interception) return [];
  const lines = ["## Withheld from this report", ""];
  if (interception) lines.push(`${INTERCEPTION_TITLE[interception.kind]}${interception.vendor ? ` (${interception.vendor})` : ""}: ${interception.signal}`, "");
  for (const w of list) lines.push(`- ${w.name} (${w.severity}): ${w.reason}`);
  lines.push("");
  return lines;
}
