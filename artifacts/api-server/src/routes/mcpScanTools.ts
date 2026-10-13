import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Request } from "express";
import type { TokenUser } from "../lib/apiTokens";
import { SEVERITY_ORDER, DEFAULT_PAGE, MAX_PAGE, text, FINISHED, MAX_CONCURRENT_WAITS, activeWaits, formatReport } from "./mcpFormat";
import { z } from "zod";
import { and } from "drizzle-orm";
import { launchScan, ownScan, reportForScan, UUID } from "./appRouteRunner";
import { APP_ORIGIN } from "../lib/appOrigin";
import { stripe } from "../lib/stripe";

/** MCP tools that start a scan and read its status and report. */
export function registerScanTools(server: McpServer, httpReq: Request, user: TokenUser): void {
  server.registerTool(
    "scan_url",
    {
      title: "Scan a website",
      description:
        "Start a SecScan security scan of a web application the user owns or is authorised to test. " +
        "Returns a scan_id; most scans finish in under a minute — then call get_scan_status with wait_seconds, or get_report. " +
        "Active tests (injection, XSS, SSRF…) run only on domains the user has verified; others get passive checks. " +
        "Optionally also reads a GitHub repository's source (github_repo): any public one, or a private one the user connected at secscan.us. That only contacts GitHub, never the site. " +
        "Each scan uses one of the user's free scans, plan scans or credits.",
      inputSchema: {
        url: z.string().min(1).max(2048).describe("The URL to scan, e.g. https://example.com"),
        github_repo: z
          .string()
          .max(300)
          .optional()
          .describe("Optional GitHub repository to read, e.g. https://github.com/owner/repo. Public, or private if the user connected it under Connect GitHub on secscan.us."),
      },
      annotations: { openWorldHint: true },
    },
    async ({ url, github_repo }) => {
      const { status, body } = await launchScan(httpReq, user, url, github_repo);
      if (status >= 400) {
        if (body?.code === "trial_exhausted") {
          // Point at checkout only when checkout exists; otherwise the server's
          // own message ("paid scans are coming soon") already says it all.
          return text(
            stripe ? `${body.error} Plans and credits: ${APP_ORIGIN}/settings#billing` : String(body.error),
            true,
          );
        }
        return text(String(body?.error ?? `The scan could not be started (HTTP ${status}).`), true);
      }
      return text(
        `Scan started. scan_id: ${body.scanId}\n` +
          `Paid with: ${body.paidWith ?? "free"}.\n` +
          `Call get_scan_status with scan_id "${body.scanId}" and wait_seconds 60 to wait for the result.`,
      );
    },
  );

  server.registerTool(
    "get_scan_status",
    {
      title: "Check a scan",
      description:
        "Status of a scan (queued, scanning, analyzing, complete, failed). With wait_seconds (max 60) it waits for " +
        "the scan to finish and returns the full report as soon as it does.",
      inputSchema: {
        scan_id: z.string().describe("The scan_id returned by scan_url"),
        wait_seconds: z.number().int().min(0).max(60).optional().describe("Wait up to this long for the scan to finish"),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ scan_id, wait_seconds }) => {
      if (!UUID.test(scan_id)) return text("No scan with that id.", true);
      const inFlight = activeWaits.get(user.id) ?? 0;
      const mayWait = (wait_seconds ?? 0) > 0 && inFlight < MAX_CONCURRENT_WAITS;
      const deadline = Date.now() + (mayWait ? (wait_seconds ?? 0) * 1000 : 0);
      if (mayWait) activeWaits.set(user.id, inFlight + 1);
      let scan: Awaited<ReturnType<typeof ownScan>>;
      try {
        scan = await ownScan(user.id, scan_id);
        while (scan && !FINISHED.has(scan.status) && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 2000));
          scan = await ownScan(user.id, scan_id);
        }
      } finally {
        if (mayWait) {
          const left = (activeWaits.get(user.id) ?? 1) - 1;
          if (left <= 0) activeWaits.delete(user.id);
          else activeWaits.set(user.id, left);
        }
      }
      if (!scan) return text("No scan with that id.", true);
      if (scan.status === "failed") return text(`The scan of ${scan.targetUrl} failed: ${scan.error ?? "unknown error"}`, true);
      if (scan.status !== "complete") {
        return text(`Scan of ${scan.targetUrl} is ${scan.status}. Check again with wait_seconds to wait for it.`);
      }
      const report = await reportForScan(user.id, scan.id);
      return text(report ? formatReport(report) : `Scan of ${scan.targetUrl} is complete; the report is still being saved — try get_report in a moment.`);
    },
  );

  server.registerTool(
    "get_report",
    {
      title: "Read a scan report",
      description:
        "The finished report for a scan: grade, what the scan tested and what it skipped (a clean grade says nothing " +
        "about skipped areas, so say so), prioritised findings with fixes and evidence, and a fix prompt " +
        `written for the user's AI editor. Findings come ${DEFAULT_PAGE} per page, most severe first — pass offset ` +
        'for the next page, or min_severity (e.g. "high") to focus on what matters most.',
      inputSchema: {
        scan_id: z.string().describe("The scan_id returned by scan_url or list_recent_scans"),
        min_severity: z.enum(SEVERITY_ORDER).optional().describe('Only findings at this severity or worse, e.g. "high"'),
        offset: z.number().int().min(0).optional().describe("Skip this many findings, for the next page"),
        limit: z.number().int().min(1).max(MAX_PAGE).optional().describe(`Findings per page (default ${DEFAULT_PAGE}, max ${MAX_PAGE})`),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ scan_id, min_severity, offset, limit }) => {
      if (!UUID.test(scan_id)) return text("No scan with that id.", true);
      const scan = await ownScan(user.id, scan_id);
      if (!scan) return text("No scan with that id.", true);
      if (scan.status !== "complete") return text(`That scan is ${scan.status}, not finished yet.`, true);
      const report = await reportForScan(user.id, scan_id);
      return report
        ? text(formatReport(report, { minSeverity: min_severity, offset, limit }))
        : text("The report is not available yet — try again in a moment.", true);
    },
  );

}
