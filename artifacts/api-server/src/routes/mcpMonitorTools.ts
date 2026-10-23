import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Request } from "express";
import type { TokenUser } from "../lib/apiTokens";
import { text, formatMonitors } from "./mcpFormat";
import { z } from "zod";
import { and } from "drizzle-orm";
import { runAppRoute, ownScan, reportForScan, UUID } from "./appRouteRunner";
import monitorRouter from "./monitor";
import dismissalsRouter from "./dismissals";
import { APP_ORIGIN } from "../lib/appOrigin";
import { stripe } from "../lib/stripe";

/** MCP tools for monitors and dismissing findings. */
export function registerMonitorTools(server: McpServer, httpReq: Request, user: TokenUser): void {
  server.registerTool(
    "list_monitors",
    {
      title: "List monitored sites",
      description:
        "Sites under continuous monitoring: latest grade, last and next scan, uptime check, CVE alerts, new problems " +
        "in the last scan and certificate expiry. Use the monitor id with monitor_scan_now.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const { status, body } = await runAppRoute(monitorRouter, "get", "/monitor/subscriptions", httpReq, user);
      if (status >= 400) return text(String(body?.error ?? "Could not list monitors."), true);
      return text(formatMonitors(Array.isArray(body) ? body : []));
    },
  );

  server.registerTool(
    "add_monitor",
    {
      title: "Monitor a site",
      description:
        "Put a site the user owns under continuous monitoring: hourly uptime checks, CVE matching, certificate alerts and " +
        "regular rescans. Runs a full baseline scan straight away, which uses one of the user's scans exactly as in the app " +
        "(free for plan holders). Returns the baseline scan_id for get_scan_status.",
      inputSchema: { url: z.string().min(1).max(2048).describe("The site to monitor, e.g. https://example.com") },
      annotations: { openWorldHint: true },
    },
    async ({ url }) => {
      const { status, body } = await runAppRoute(monitorRouter, "post", "/monitor/subscriptions", httpReq, user, {
        body: { targetUrl: url },
      });
      if (status >= 400) {
        const extra = body?.code === "trial_exhausted" && stripe ? ` Plans and credits: ${APP_ORIGIN}/settings#billing` : "";
        return text(`${String(body?.error ?? `Could not add the monitor (HTTP ${status}).`)}${extra}`, true);
      }
      return text(
        `Now monitoring ${body.subscription.targetUrl} (monitor id ${body.subscription.id}).\n` +
          (body.initialScanId
            ? `Baseline scan started: scan_id ${body.initialScanId}. Call get_scan_status with wait_seconds 60 for the result.`
            : "The baseline scan could not be queued (you were not charged); the scheduler will scan it shortly."),
      );
    },
  );

  server.registerTool(
    "monitor_scan_now",
    {
      title: "Rescan a monitored site now",
      description:
        "Run a full scan of a monitored site now instead of waiting for its schedule — e.g. to confirm a fix. Free for plan " +
        "holders; otherwise uses one of the user's scans, as in the app. Takes the monitor id from list_monitors.",
      inputSchema: { monitor_id: z.string().describe("The monitor id from list_monitors or add_monitor") },
      annotations: { openWorldHint: true },
    },
    async ({ monitor_id }) => {
      if (!UUID.test(monitor_id)) return text("No monitor with that id.", true);
      const { status, body } = await runAppRoute(monitorRouter, "post", "/monitor/subscriptions/:id/scan", httpReq, user, {
        params: { id: monitor_id },
      });
      if (status === 404) return text("No monitor with that id.", true);
      if (status >= 400) return text(String(body?.error ?? `Could not start the scan (HTTP ${status}).`), true);
      return text(`Scan started: scan_id ${body.scanId}. Call get_scan_status with wait_seconds 60 for the result.`);
    },
  );

  // ── Findings ─────────────────────────────────────────────────────────────

  server.registerTool(
    "dismiss_finding",
    {
      title: "Dismiss a false positive",
      description:
        "Mark a finding as a false positive for this site, so future scans of it stop reporting it — the same as " +
        "Dismiss in the app, and undoable there. ONLY use this after the user has confirmed the finding is wrong; never " +
        "dismiss a real problem to improve a grade.",
      inputSchema: {
        scan_id: z.string().describe("The scan whose report contains the finding"),
        finding_name: z.string().min(1).max(300).describe("The finding's name exactly as get_report shows it"),
      },
      annotations: { destructiveHint: true },
    },
    async ({ scan_id, finding_name }) => {
      if (!UUID.test(scan_id)) return text("No scan with that id.", true);
      const scan = await ownScan(user.id, scan_id);
      const report = scan ? await reportForScan(user.id, scan_id) : null;
      if (!scan || !report) return text("No finished scan with that id.", true);
      // Taken from the report, not from the caller: an editor can only dismiss
      // a finding the scan actually produced, with its real category and evidence.
      const data = report.data as { vulnerabilities?: any[] } | null;
      const vulns = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
      const wanted = finding_name.trim().toLowerCase();
      const matches = vulns.filter((v) => String(v.name).trim().toLowerCase() === wanted);
      if (matches.length === 0) {
        return text(`That report has no finding named "${finding_name}". Use the name exactly as get_report shows it.`, true);
      }
      for (const v of matches) {
        const { status, body } = await runAppRoute(dismissalsRouter, "post", "/dismissals", httpReq, user, {
          body: {
            targetUrl: scan.targetUrl,
            findingName: v.name,
            findingCategory: v.category,
            findingEvidence: v.evidence ?? undefined,
            reason: "false_positive",
          },
        });
        if (status >= 400) return text(String(body?.error ?? "Could not dismiss the finding."), true);
      }
      return text(
        `Dismissed "${matches[0].name}" for ${scan.targetUrl}` +
          `${matches.length > 1 ? ` (${matches.length} occurrences)` : ""}. Future scans of this site will not report it. ` +
          `Undo it from the report in the app: ${APP_ORIGIN}/report/${report.id}`,
      );
    },
  );

}
