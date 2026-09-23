/**
 * Remote MCP endpoint — lets an AI editor (Claude Code, Cursor, …) scan a site
 * and read the findings without the user leaving it.
 *
 *   claude mcp add --transport http secscan https://secscan.us/api/mcp \
 *     --header "Authorization: Bearer ssk_…"
 *
 * Stateless Streamable HTTP: a fresh server per request, bound to the user the
 * API token belongs to. Nothing is held between requests, so it runs on every
 * replica with no session affinity.
 *
 * The one rule this file exists to keep: NO SIDE DOOR. scan_url does not launch
 * scans itself — it runs the website's own handler (createScanHandler) after
 * the website's own rate limiters, so the free trial, credits and plan scans,
 * the SSRF guard, domain-ownership gating of active tests and every validation
 * apply exactly as they do in the browser. Reads are scoped to the token's
 * owner in every query.
 */
import { Router, type IRouter, type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { db, scansTable, reportsTable, domainVerificationsTable } from "@workspace/db";
import { and, desc, eq, isNotNull } from "drizzle-orm";
import { authenticateApiToken, type TokenUser } from "../lib/apiTokens";
import { createScanHandler, scanRateLimit, scanNetworkRateLimit } from "./scans";
import { APP_ORIGIN } from "../lib/appOrigin";
import { stripe } from "../lib/stripe";

const router: IRouter = Router();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
/** Findings returned by get_report. A long tail of info notes would crowd an editor's context. */
const MAX_FINDINGS = 60;
const MAX_EVIDENCE_CHARS = 400;

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: "text", text: t }], ...(isError ? { isError } : {}) });

/**
 * Run the website's scan-launch handler for this user and capture its answer.
 * Only the fields that handler reads are supplied (see createScanHandler).
 */
async function launchScan(httpReq: Request, user: TokenUser, url: string): Promise<{ status: number; body: any }> {
  // A request-shaped object carrying the token's user and the REAL client
  // address, so the per-user and per-network limits count against the same
  // buckets as the website — an editor gets no extra allowance.
  const asUser = Object.assign(Object.create(httpReq), {
    user,
    body: { targetUrl: url },
    isAuthenticated: () => true,
  }) as Request;

  for (const limiter of [scanRateLimit, scanNetworkRateLimit]) {
    const decision = limiter.decide(asUser);
    if (!decision.allowed) {
      return {
        status: 429,
        body: { error: `Rate limit reached — at most ${decision.rule?.max} scans per ${decision.rule?.label}. Try again in ${decision.retryAfterSeconds} seconds.` },
      };
    }
  }

  let status = 200;
  let body: any = null;
  const res = {
    status(code: number) { status = code; return res; },
    json(payload: unknown) { body = payload; return res; },
    setHeader() { return res; },
    end() { return res; },
  } as unknown as Response;

  await createScanHandler(asUser, res);
  return { status, body };
}

async function ownScan(userId: string, scanId: string) {
  const [scan] = await db
    .select({
      id: scansTable.id,
      targetUrl: scansTable.targetUrl,
      status: scansTable.status,
      error: scansTable.error,
      createdAt: scansTable.createdAt,
      completedAt: scansTable.completedAt,
    })
    .from(scansTable)
    .where(and(eq(scansTable.id, scanId), eq(scansTable.userId, userId)))
    .limit(1);
  return scan ?? null;
}

async function reportForScan(userId: string, scanId: string) {
  const [report] = await db
    .select({ id: reportsTable.id, targetUrl: reportsTable.targetUrl, scannedAt: reportsTable.scannedAt, data: reportsTable.data })
    .from(reportsTable)
    .where(and(eq(reportsTable.scanId, scanId), eq(reportsTable.userId, userId)))
    .limit(1);
  return report ?? null;
}

const FINISHED = new Set(["complete", "failed"]);

/** A plain-text report sized for an editor's context window. */
function formatReport(report: { id: string; targetUrl: string; scannedAt: Date; data: any }): string {
  const d = report.data ?? {};
  const s = d.summary ?? {};
  const vulns: any[] = Array.isArray(d.vulnerabilities) ? d.vulnerabilities : [];
  const sorted = [...vulns].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const shown = sorted.slice(0, MAX_FINDINGS);

  const lines: string[] = [
    `SecScan report for ${report.targetUrl} (scanned ${report.scannedAt.toISOString()})`,
    `Grade ${s.grade ?? "?"} · risk score ${s.riskScore ?? "?"}/100 · ${s.critical ?? 0} critical, ${s.high ?? 0} high, ${s.medium ?? 0} medium, ${s.low ?? 0} low, ${s.info ?? 0} info`,
    `Full report: ${APP_ORIGIN}/report/${report.id}`,
    "",
  ];
  if (s.executiveSummary) lines.push("Summary:", String(s.executiveSummary), "");

  const ai = d.aiAnalysis;
  if (ai?.topPriorities?.length) {
    lines.push("Top priorities:", ...ai.topPriorities.map((p: string, i: number) => `${i + 1}. ${p}`), "");
  }
  if (ai?.agentFixPrompt) {
    lines.push("Fix prompt (written for this codebase's AI editor — act on it directly):", String(ai.agentFixPrompt), "");
  }

  lines.push(`Findings (${vulns.length}${vulns.length > shown.length ? `, showing the ${shown.length} most severe` : ""}):`);
  for (const v of shown) {
    lines.push(
      "",
      `[${String(v.severity).toUpperCase()}] ${v.name}${v.cweId ? ` (${v.cweId})` : ""}`,
      `What: ${v.description}`,
      `Fix: ${v.solution}`,
    );
    if (v.evidence) {
      const ev = String(v.evidence);
      lines.push(`Evidence: ${ev.length > MAX_EVIDENCE_CHARS ? ev.slice(0, MAX_EVIDENCE_CHARS) + "…" : ev}`);
    }
  }
  if (d.compliance?.disclaimer) lines.push("", `Compliance mapping note: ${d.compliance.disclaimer}`);
  return lines.join("\n");
}

function buildServer(httpReq: Request, user: TokenUser): McpServer {
  const server = new McpServer({ name: "secscan", version: "1.0.0" });

  server.registerTool(
    "scan_url",
    {
      title: "Scan a website",
      description:
        "Start a SecScan security scan of a web application the user owns or is authorised to test. " +
        "Returns a scan_id; most scans finish in under a minute — then call get_scan_status with wait_seconds, or get_report. " +
        "Active tests (injection, XSS, SSRF…) run only on domains the user has verified; others get passive checks. " +
        "Each scan uses one of the user's free scans, plan scans or credits.",
      inputSchema: { url: z.string().min(1).max(2048).describe("The URL to scan, e.g. https://example.com") },
      annotations: { openWorldHint: true },
    },
    async ({ url }) => {
      const { status, body } = await launchScan(httpReq, user, url);
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
      const deadline = Date.now() + (wait_seconds ?? 0) * 1000;
      let scan = await ownScan(user.id, scan_id);
      while (scan && !FINISHED.has(scan.status) && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 2000));
        scan = await ownScan(user.id, scan_id);
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
        "The finished report for a scan: grade, prioritised findings with fixes and evidence, and a fix prompt " +
        "written for the user's AI editor.",
      inputSchema: { scan_id: z.string().describe("The scan_id returned by scan_url or list_recent_scans") },
      annotations: { readOnlyHint: true },
    },
    async ({ scan_id }) => {
      if (!UUID.test(scan_id)) return text("No scan with that id.", true);
      const scan = await ownScan(user.id, scan_id);
      if (!scan) return text("No scan with that id.", true);
      if (scan.status !== "complete") return text(`That scan is ${scan.status}, not finished yet.`, true);
      const report = await reportForScan(user.id, scan_id);
      return report ? text(formatReport(report)) : text("The report is not available yet — try again in a moment.", true);
    },
  );

  server.registerTool(
    "list_recent_scans",
    {
      title: "List recent scans",
      description: "The user's most recent scans with their status, newest first.",
      inputSchema: { limit: z.number().int().min(1).max(25).optional() },
      annotations: { readOnlyHint: true },
    },
    async ({ limit }) => {
      const rows = await db
        .select({ id: scansTable.id, targetUrl: scansTable.targetUrl, status: scansTable.status, createdAt: scansTable.createdAt })
        .from(scansTable)
        .where(eq(scansTable.userId, user.id))
        .orderBy(desc(scansTable.createdAt))
        .limit(limit ?? 10);
      if (rows.length === 0) return text("No scans yet.");
      return text(rows.map((r) => `${r.id}  ${r.status.padEnd(9)}  ${r.createdAt.toISOString()}  ${r.targetUrl}`).join("\n"));
    },
  );

  server.registerTool(
    "list_verified_domains",
    {
      title: "List verified domains",
      description:
        "Domains the user has proved they own. Only these receive active testing (injection, XSS, SSRF, access control); " +
        `others get passive checks. Verify more at ${APP_ORIGIN}/domains.`,
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const rows = await db
        .select({ domain: domainVerificationsTable.domain })
        .from(domainVerificationsTable)
        // The same test the active-probe gate applies (lib/activeProbeGate.ts):
        // a verification counts once verified_at is set. Exact hostname only.
        .where(and(eq(domainVerificationsTable.userId, user.id), isNotNull(domainVerificationsTable.verifiedAt)));
      const verified = rows.map((r) => r.domain);
      return text(
        verified.length
          ? `Verified (full active testing): ${verified.join(", ")}`
          : `No verified domains yet — scans get passive checks only. Verify one at ${APP_ORIGIN}/domains.`,
      );
    },
  );

  return server;
}

router.post("/mcp", async (req, res): Promise<void> => {
  const user = await authenticateApiToken(req.headers["authorization"]);
  if (!user) {
    res
      .status(401)
      .setHeader("WWW-Authenticate", 'Bearer realm="secscan"')
      .json({ error: `Missing or invalid API token. Create one at ${APP_ORIGIN}/settings#ai-editors.` });
    return;
  }

  const server = buildServer(req, user);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    req.log.error({ err }, "MCP request failed");
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  }
});

// Stateless: there is no server-initiated stream to open and no session to end.
router.get("/mcp", (_req, res) => {
  res.status(405).setHeader("Allow", "POST").json({ error: "Use POST." });
});
router.delete("/mcp", (_req, res) => {
  res.status(405).setHeader("Allow", "POST").json({ error: "Use POST." });
});

export default router;
