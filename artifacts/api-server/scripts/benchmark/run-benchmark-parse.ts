/** Turning each tool's raw output into the common finding shape. */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { OUT_DIR } from "./run-benchmark-config";

// ── A normalised finding, whatever produced it ────────────────────────────────

export interface Normalised {
  /** Everything the tool said, lowercased, for matching against. */
  haystack: string;
  /** The tool's own headline name, for printing in the report. */
  name: string;
  severity: string;
}

// ── Parsers ───────────────────────────────────────────────────────────────────

export function parseZap(): Normalised[] {
  const path = join(OUT_DIR, "zap.json");
  if (!existsSync(path)) return [];
  const doc = JSON.parse(readFileSync(path, "utf8")) as {
    site?: Array<{ alerts?: Array<Record<string, unknown>> }>;
  };
  const out: Normalised[] = [];
  for (const site of doc.site ?? []) {
    for (const a of site.alerts ?? []) {
      const instances = (a["instances"] as Array<Record<string, unknown>>) ?? [];
      // NAME + per-instance evidence only.
      //
      // ZAP's desc/solution/reference fields are generic security education
      // text — paragraphs that mention cookies, CORS, CSP and XSS regardless of
      // what was actually found. Including them made almost every matcher hit
      // almost every alert: a first pass credited ZAP with finding reflected
      // XSS on the strength of a CORS alert, and path traversal on the strength
      // of a cross-domain script include. It scored ZAP 44/74 on prose.
      //
      // Only the alert name and the instance-specific fields describe what this
      // particular alert found, so only those are matched against.
      const parts = [
        a["alert"], a["name"], a["cweid"] ? `CWE-${a["cweid"]}` : "",
        // NOT the instance URI. A URI in the haystack means only that the tool
        // visited that path — it credited ZAP with "finding" .env exposed
        // because ZAP reported a CORS issue AT /.env, having never flagged the
        // file exposure at all.
        ...instances.flatMap((i) => [i["evidence"], i["param"]]),
      ];
      out.push({
        name: String(a["alert"] ?? a["name"] ?? "(unnamed)"),
        severity: String(a["riskdesc"] ?? "").split(" ")[0] || "unknown",
        haystack: parts.filter(Boolean).join(" ").toLowerCase(),
      });
    }
  }
  return out;
}

export function parseNuclei(): Normalised[] {
  const path = join(OUT_DIR, "nuclei.jsonl");
  if (!existsSync(path)) return [];
  const out: Normalised[] = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let r: Record<string, unknown>;
    try { r = JSON.parse(line); } catch { continue; }
    const info = (r["info"] as Record<string, unknown>) ?? {};
    // Template id, name, tags and the matched URL. info.description is
    // dropped for the same reason ZAP's desc is — see parseZap.
    const parts = [
      r["template-id"], r["template-path"], r["type"],
      info["name"], (info["tags"] as string[] | undefined)?.join(" "),
      r["extracted-results"] ? JSON.stringify(r["extracted-results"]) : "",
    ];
    out.push({
      name: String(info["name"] ?? r["template-id"] ?? "(unnamed)"),
      severity: String(info["severity"] ?? "unknown"),
      haystack: parts.filter(Boolean).join(" ").toLowerCase(),
    });
  }
  return out;
}

export function parseSecscan(): Normalised[] {
  const path = join(OUT_DIR, "secscan.json");
  if (!existsSync(path)) return [];
  const doc = JSON.parse(readFileSync(path, "utf8")) as {
    results?: Array<{ findings?: Array<Record<string, unknown>> }>;
  };
  const out: Normalised[] = [];
  for (const site of doc.results ?? []) {
    for (const f of site.findings ?? []) {
      const parts = [f["name"], f["category"], f["cweId"], f["wstgId"], f["evidence"]];
      out.push({
        name: String(f["name"] ?? "(unnamed)"),
        severity: String(f["severity"] ?? "unknown"),
        haystack: parts.filter(Boolean).join(" ").toLowerCase(),
      });
    }
  }
  return out;
}
