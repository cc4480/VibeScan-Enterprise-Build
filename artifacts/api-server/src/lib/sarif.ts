/**
 * A finished report as SARIF 2.1.0, the format GitHub code scanning and most CI
 * tools read.
 *
 * SecScan scans a running site, not source files, so a result has no file and line.
 * Its location is the URL it was found at, which is how other DAST tools (ZAP,
 * for one) report into SARIF. GitHub shows such results as alerts on the
 * repository; it cannot show them inline in a diff, and this file does not pretend
 * otherwise.
 *
 * Scan-coverage notices ("Active testing was skipped", "Scan session expired") are not
 * security findings, so they are not results: as alerts they would appear in the
 * Security tab on every scan of an unverified site. They go in the run's
 * notifications instead, which is what SARIF provides for messages from the tool.
 *
 * Rules are keyed by finding name, so the same problem on two scans is the same
 * alert and a fix closes it. Severity maps to a SARIF level for CI gating and to
 * GitHub's numeric security-severity for how the alert is ranked.
 */
import { createHash } from "node:crypto";

const SEVERITY_LEVEL: Record<string, "error" | "warning" | "note"> = {
  critical: "error", high: "error", medium: "warning", low: "note", info: "note",
};
/** GitHub ranks alerts by this number (critical 9.0+, high 7.0+, medium 4.0+, low below). */
const SEVERITY_SCORE: Record<string, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** A stable, readable rule id from a finding name. */
export function ruleId(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
  const tail = createHash("sha1").update(name).digest("hex").slice(0, 6);
  return `secscan/${slug || "finding"}-${tail}`;
}

/** The URL a finding was observed at, from its evidence ("GET https://…"), else the scanned site. */
export function locationUrl(evidence: string, fallback: string): string {
  const m = /\b(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(https?:\/\/[^\s"'<>]+)/i.exec(evidence);
  return m?.[1] ?? fallback;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "unknown";
  }
}

export interface SarifInput {
  targetUrl: string;
  scannedAt?: string | Date | null;
  data: unknown;
}

export function toSarif({ targetUrl, scannedAt, data }: SarifInput) {
  const report = isRecord(data) ? data : {};
  const all = (Array.isArray(report["vulnerabilities"]) ? report["vulnerabilities"] : []).filter(isRecord);
  const isNotice = (v: Record<string, unknown>) => str(v["category"]) === "Scan Coverage";
  const vulns = all.filter((v) => !isNotice(v));
  const notifications = all.filter(isNotice).map((v) => ({
    level: "note" as const,
    message: { text: `${str(v["name"])}: ${str(v["description"])}`.slice(0, 1000) },
  }));

  const rules = new Map<string, Record<string, unknown>>();
  const results = vulns.map((v) => {
    const name = str(v["name"]) || "Finding";
    const severity = str(v["severity"]).toLowerCase();
    const id = ruleId(name);
    const cwe = str(v["cweId"]);

    if (!rules.has(id)) {
      rules.set(id, {
        id,
        name: name.replace(/[^A-Za-z0-9]+/g, ""),
        shortDescription: { text: name },
        fullDescription: { text: str(v["description"]) || name },
        help: { text: str(v["solution"]) || "See the SecScan report for the fix.", markdown: str(v["solution"]) || undefined },
        defaultConfiguration: { level: SEVERITY_LEVEL[severity] ?? "note" },
        properties: {
          "security-severity": SEVERITY_SCORE[severity] ?? "1.0",
          tags: ["security", ...(str(v["category"]) ? [str(v["category"])] : []), ...(cwe ? [cwe] : [])],
        },
      });
    }

    const at = locationUrl(str(v["evidence"]), targetUrl);
    return {
      ruleId: id,
      level: SEVERITY_LEVEL[severity] ?? "note",
      message: { text: str(v["description"]) || name },
      locations: [{ physicalLocation: { artifactLocation: { uri: at }, region: { startLine: 1 } } }],
      // Same finding at the same place is the same alert across scans.
      partialFingerprints: { "secscanFinding/v1": createHash("sha256").update(`${id}|${at}`).digest("hex").slice(0, 32) },
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "SecScan", informationUri: "https://secscan.info", rules: [...rules.values()] } },
        automationDetails: { id: `secscan/${hostOf(targetUrl)}` },
        invocations: [
          {
            executionSuccessful: true,
            ...(scannedAt ? { endTimeUtc: new Date(scannedAt).toISOString() } : {}),
            ...(notifications.length ? { toolExecutionNotifications: notifications } : {}),
          },
        ],
        results,
      },
    ],
  };
}
