import { APP_ORIGIN } from "../lib/appOrigin";
import { coverageLines, sourceLines } from "../lib/testLedger";
import { and } from "drizzle-orm";
import { splitScanNotes } from "../lib/scanNotes";

/** Formatting and limits shared by the MCP tools: report/account/monitor text, the tool-result shape and the server instructions. */



export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

/**
 * Findings per page. Measured on a real scan of the vuln-fixture (180
 * findings): 60 per page came to ~37k characters (~9.5k tokens), past
 * Claude Code's MCP-output warning and a heavy share of an editor's context.
 * 25 per page is roughly 15k characters; the rest is reachable with offset.
 */
export const DEFAULT_PAGE = 25;

export const MAX_PAGE = 50;

export const MAX_EVIDENCE_CHARS = 300;

export const MAX_TEXT_CHARS = 600;

export const clip = (v: unknown, n: number): string => {
  const t = String(v ?? "");
  return t.length > n ? t.slice(0, n) + "…" : t;
};

export type Severity = (typeof SEVERITY_ORDER)[number];

export interface ReportPage {
  offset?: number;
  limit?: number;
  minSeverity?: Severity;
}

export type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

export const text = (t: string, isError = false): ToolResult => ({ content: [{ type: "text", text: t }], ...(isError ? { isError } : {}) });

export const FINISHED = new Set(["complete", "failed"]);

/**
 * Concurrent get_scan_status waits per user, per replica. A wait holds an HTTP
 * connection open and polls the database every 2s for up to 60s, so a client
 * that fires many at once would pin connections for nothing. Past the cap the
 * call still answers — with the current status, immediately.
 */
export const MAX_CONCURRENT_WAITS = 3;

export const activeWaits = new Map<string, number>();

/** How a well-behaved client should use these tools — sent to the client at connect. */
export const SERVER_INSTRUCTIONS = [
  "SecScan scans a live web application from the outside and reports its security problems.",
  "Only scan applications the user owns or is authorised to test.",
  "Typical flow: scan_url -> get_scan_status with wait_seconds 60 (most scans finish in under a minute, and the",
  "call returns the report as soon as it does) -> for a large report, get_report with offset for more pages, or",
  'min_severity "high" to focus. Work through critical and high findings first, and use the fix prompt in the',
  "report — it is written for the user's editor. Active tests (injection, XSS, SSRF, access control) run only on",
  "domains listed by list_verified_domains; say so if a scan was passive-only. Each scan spends one of the user's",
  "free scans, plan scans or credits, so do not start a scan the user did not ask for. The same applies to",
  "add_monitor and monitor_scan_now; get_account says how many scans are left. To unlock active tests, use",
  "start_domain_verification, publish the file or DNS record it returns, then check_domain_verification.",
  "Only call dismiss_finding when the user has confirmed a finding is a false positive — never to improve a grade.",
].join(" ");

/**
 * A plain-text report sized for an editor's context window: one page of
 * findings at a time, most severe first. Exported for tests.
 */
export function formatReport(
  report: { id: string; targetUrl: string; scannedAt: Date; data: any },
  page: ReportPage = {},
): string {
  const d = report.data ?? {};
  const s = d.summary ?? {};
  const listed = Array.isArray(d.vulnerabilities);
  // The scan's own notes are listed apart from the findings and are in none of the counts (lib/scanNotes.ts).
  const { findings: vulns, notes }: { findings: any[]; notes: any[] } = splitScanNotes<any>(listed ? d.vulnerabilities : []);
  // Counted from the list, so the line and the list agree on a report saved before notes were left out of its summary.
  const n = (sev: Severity): number => (listed ? vulns.filter((v) => v.severity === sev).length : (s[sev] ?? 0));
  const floor = SEVERITY_ORDER.indexOf(page.minSeverity ?? "info");
  const sorted = vulns
    .filter((v) => {
      const rank = SEVERITY_ORDER.indexOf(v.severity);
      return rank !== -1 && rank <= floor;
    })
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const offset = Math.max(0, page.offset ?? 0);
  const limit = Math.min(MAX_PAGE, Math.max(1, page.limit ?? DEFAULT_PAGE));
  const shown = sorted.slice(offset, offset + limit);
  const firstPage = offset === 0;

  const lines: string[] = [
    `SecScan report for ${report.targetUrl} (scanned ${report.scannedAt.toISOString()})`,
    `Grade ${s.grade ?? "?"} · risk score ${s.riskScore ?? "?"}/100 · ${n("critical")} critical, ${n("high")} high, ${n("medium")} medium, ${n("low")} low, ${n("info")} info`,
    `Full report: ${APP_ORIGIN}/report/${report.id}`,
    "",
  ];
  // Next to the grade, on the first page: a clean grade must not read as full
  // coverage when active tests or access-control tests were skipped.
  if (firstPage) lines.push(...sourceLines(d.tests, vulns), ...coverageLines(d.tests));
  // The narrative belongs to the report, not to a page — sent once, on page 1.
  const ai = d.aiAnalysis;
  if (firstPage) {
    if (s.executiveSummary) lines.push("Summary:", String(s.executiveSummary), "");
    if (ai?.topPriorities?.length) {
      lines.push("Top priorities:", ...ai.topPriorities.map((p: string, i: number) => `${i + 1}. ${p}`), "");
    }
    if (ai?.agentFixPrompt) {
      lines.push("Fix prompt (tool-neutral, written to work in any AI coding tool — act on it directly):", String(ai.agentFixPrompt), "");
    }
  }

  const filterNote = page.minSeverity && page.minSeverity !== "info" ? ` at ${page.minSeverity} or above` : "";
  if (sorted.length === 0) {
    lines.push(
      notes.length > 0 && !filterNote
        ? "No findings were reported. Read the notes under “About this scan” below before treating that as a clean result: they say what the scan could not check."
        : `No findings${filterNote}.`,
    );
  } else if (shown.length === 0) {
    lines.push(`No findings at offset ${offset} — there are ${sorted.length}${filterNote}.`);
  } else {
    lines.push(`Findings ${offset + 1}–${offset + shown.length} of ${sorted.length}${filterNote}, most severe first:`);
  }
  for (const v of shown) {
    lines.push(
      "",
      `[${String(v.severity).toUpperCase()}] ${v.name}${v.cweId ? ` (${v.cweId})` : ""}`,
      `What: ${clip(v.description, MAX_TEXT_CHARS)}`,
      `Fix: ${clip(v.solution, MAX_TEXT_CHARS)}`,
    );
    if (v.evidence) lines.push(`Evidence: ${clip(v.evidence, MAX_EVIDENCE_CHARS)}`);
  }
  const next = offset + shown.length;
  if (shown.length > 0 && next < sorted.length) {
    lines.push(
      "",
      `${sorted.length - next} more. Call get_report with offset ${next}` +
        `${page.minSeverity ? ` and min_severity "${page.minSeverity}"` : ""} to continue.`,
    );
  }
  if (firstPage && notes.length > 0) {
    lines.push(
      "",
      `About this scan (${notes.length} note${notes.length === 1 ? "" : "s"}): what the scan could and could not check. They describe the scan, not the site.`,
      ...notes.map((v) => `- ${v.name}: ${clip(v.description, MAX_TEXT_CHARS)}`),
    );
  }
  if (firstPage && d.compliance?.disclaimer) lines.push("", `Compliance mapping note: ${d.compliance.disclaimer}`);
  return lines.join("\n");
}

/** The hostname from "example.com", "https://example.com/path" or similar; the input unchanged if unparseable. */
export function hostOf(domain: string): string {
  try {
    return new URL(/^https?:\/\//i.test(domain) ? domain : `https://${domain}`).hostname;
  } catch {
    return domain;
  }
}

/** GET /billing/status, as text. Exported for tests. */
export function formatAccount(b: any): string {
  const sub = b.subscription;
  return [
    `Free scans left this month: ${b.freeScansRemaining} of ${b.freeScanLimit}` +
      (b.freeScansResetAt ? ` · renew ${String(b.freeScansResetAt).slice(0, 10)}` : ""),
    // Credits are no longer sold, so the line is shown only to someone who still holds some.
    ...(b.credits > 0 ? [`Credits: ${b.credits}`] : []),
    sub
      ? `Plan: ${sub.plan} (${sub.status}) · ` +
        (sub.unlimitedScans ? "unlimited scans" : `${sub.includedScansRemaining} included scans left this period`) +
        ` · up to ${sub.urlLimit} monitored sites` +
        (sub.currentPeriodEnd ? ` · renews ${String(sub.currentPeriodEnd).slice(0, 10)}` : "")
      : "Plan: none",
    b.paymentsEnabled ? `Plan: ${APP_ORIGIN}/settings#billing` : "Subscribing is not open yet.",
  ].join("\n");
}

/** One domain verification, as text: its state, or exactly what to publish. Exported for tests. */
export function formatVerification(v: any): string {
  if (v.verified) {
    return `Domain: ${v.domain} — VERIFIED (${v.method === "dns" ? "DNS record" : "file"}). Its scans now include active tests.`;
  }
  return [
    `Domain: ${v.domain} — not verified yet.`,
    "Prove ownership with EITHER of these, then call check_domain_verification:",
    `  File: serve exactly this text at ${v.wellKnown.url}`,
    `        ${v.wellKnown.content}`,
    `  DNS:  a TXT record named ${v.dns.name} with the value ${v.dns.value}`,
  ].join("\n");
}

/** GET /monitor/subscriptions, as text — active monitors only. Exported for tests. */
export function formatMonitors(subs: any[]): string {
  const active = subs.filter((m) => m.status === "active");
  if (active.length === 0) return `No sites are being monitored. Add one with add_monitor, or at ${APP_ORIGIN}/monitor.`;
  const when = (d: unknown) => (d ? new Date(String(d)).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "—");
  return active
    .map((m) => {
      const uptime =
        m.pulseReachable == null
          ? "not run yet"
          : m.pulseReachable
            ? `up (HTTP ${m.pulseStatus}, ${m.responseTimeMs} ms)`
            : `DOWN — ${m.pulseFailureReason ?? `HTTP ${m.pulseStatus}`}`;
      return [
        `${m.targetUrl}  (monitor id ${m.id})`,
        `  Grade ${m.lastReport?.grade ?? "—"}` +
          (m.lastReport?.riskScore != null ? ` · risk ${m.lastReport.riskScore}/100` : "") +
          ` · last scan ${when(m.lastScanAt)} · next ${when(m.nextScanAt)}` +
          (m.scanInProgress ? ` · a scan is ${m.scanStatus} now` : ""),
        `  Uptime: ${uptime} · CVE alerts: ${m.alertCount ?? 0} · new problems in last scan: ${m.regressionCount ?? 0}` +
          (m.certExpiryDays != null ? ` · certificate expires in ${m.certExpiryDays} days` : ""),
        ...(m.lastReport?.id ? [`  Latest report: ${APP_ORIGIN}/report/${m.lastReport.id}`] : []),
      ].join("\n");
    })
    .join("\n\n");
}
