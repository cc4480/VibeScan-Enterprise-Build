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
import monitorRouter from "./monitor";
import domainVerificationRouter from "./domainVerification";
import dismissalsRouter from "./dismissals";
import checkoutRouter from "./checkout";
import { APP_ORIGIN } from "../lib/appOrigin";
import { coverageLines } from "../lib/testLedger";
import { stripe } from "../lib/stripe";
import { rateLimitMiddleware } from "../lib/rateLimit";

const router: IRouter = Router();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
/**
 * Findings per page. Measured on a real scan of the vuln-fixture (180
 * findings): 60 per page came to ~37k characters (~9.5k tokens), past
 * Claude Code's MCP-output warning and a heavy share of an editor's context.
 * 25 per page is roughly 15k characters; the rest is reachable with offset.
 */
const DEFAULT_PAGE = 25;
const MAX_PAGE = 50;
const MAX_EVIDENCE_CHARS = 300;
const MAX_TEXT_CHARS = 600;
const clip = (v: unknown, n: number): string => {
  const t = String(v ?? "");
  return t.length > n ? t.slice(0, n) + "…" : t;
};
type Severity = (typeof SEVERITY_ORDER)[number];

export interface ReportPage {
  offset?: number;
  limit?: number;
  minSeverity?: Severity;
}

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

interface RouteLayer {
  route?: {
    path: string;
    methods: Record<string, boolean>;
    stack: { handle: (req: Request, res: Response, next: (err?: unknown) => void) => unknown }[];
  };
}

/**
 * Run one of the website's own routes for this user — its whole handler chain,
 * middleware (auth checks, rate limiters) included — and capture the answer.
 *
 * This is how every tool beyond scan_url keeps the NO SIDE DOOR rule: adding a
 * monitor, "scan now", verifying a domain and dismissing a finding charge,
 * limit, validate and refuse exactly as the browser does, because they ARE the
 * browser's code path. A route that is renamed or removed fails loudly here
 * (the tool reports an error) rather than silently doing something else.
 */
export async function runAppRoute(
  router: unknown,
  method: "get" | "post" | "delete",
  path: string,
  httpReq: Request,
  user: TokenUser,
  input: { body?: unknown; params?: Record<string, string>; query?: Record<string, string> } = {},
): Promise<{ status: number; body: any }> {
  const layer = (router as { stack: RouteLayer[] }).stack.find((l) => l.route?.path === path && l.route.methods[method]);
  if (!layer?.route) throw new Error(`MCP: no ${method.toUpperCase()} ${path} route to run`);

  // defineProperties, not Object.assign: Express 5 defines req.query as a
  // getter-only accessor on the request prototype, so assigning it throws
  // ("Cannot set property query … which has only a getter"). Own data
  // properties shadow the accessor instead.
  const own = (value: unknown) => ({ value, writable: true, enumerable: true, configurable: true });
  const asUser = Object.create(httpReq, {
    user: own(user),
    body: own(input.body ?? {}),
    params: own(input.params ?? {}),
    query: own(input.query ?? {}),
    isAuthenticated: own(() => true),
  }) as Request;

  let status = 200;
  let body: any = null;
  let answered = false;
  const res = {
    status(code: number) { status = code; return res; },
    json(payload: unknown) { body = payload; answered = true; return res; },
    setHeader() { return res; },
    end() { answered = true; return res; },
  } as unknown as Response;

  for (const { handle } of layer.route.stack) {
    let proceed = false;
    let failure: unknown;
    await handle(asUser, res, (err?: unknown) => { proceed = true; failure = err; });
    if (failure) throw failure;
    if (answered || !proceed) break;
  }
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

/**
 * Requests per user per minute, across all tools. Scans already have their own
 * (stricter) limits; this bounds the reads — an editor stuck in a loop calling
 * get_report should not be able to hammer the database. A normal session makes
 * a handful of calls a minute.
 */
const mcpRateLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60_000, max: 120, label: "minute" }],
  name: "mcp",
  keyFrom: (req) => (req.isAuthenticated() ? `mcp:${req.user.id}` : undefined),
});

/**
 * Concurrent get_scan_status waits per user, per replica. A wait holds an HTTP
 * connection open and polls the database every 2s for up to 60s, so a client
 * that fires many at once would pin connections for nothing. Past the cap the
 * call still answers — with the current status, immediately.
 */
const MAX_CONCURRENT_WAITS = 3;
const activeWaits = new Map<string, number>();

/** How a well-behaved client should use these tools — sent to the client at connect. */
const SERVER_INSTRUCTIONS = [
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
  const vulns: any[] = Array.isArray(d.vulnerabilities) ? d.vulnerabilities : [];
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
    `Grade ${s.grade ?? "?"} · risk score ${s.riskScore ?? "?"}/100 · ${s.critical ?? 0} critical, ${s.high ?? 0} high, ${s.medium ?? 0} medium, ${s.low ?? 0} low, ${s.info ?? 0} info`,
    `Full report: ${APP_ORIGIN}/report/${report.id}`,
    "",
  ];
  // Next to the grade, on the first page: a clean grade must not read as full
  // coverage when active tests or access-control tests were skipped.
  if (firstPage) lines.push(...coverageLines(d.tests));
  // The narrative belongs to the report, not to a page — sent once, on page 1.
  const ai = d.aiAnalysis;
  if (firstPage) {
    if (s.executiveSummary) lines.push("Summary:", String(s.executiveSummary), "");
    if (ai?.topPriorities?.length) {
      lines.push("Top priorities:", ...ai.topPriorities.map((p: string, i: number) => `${i + 1}. ${p}`), "");
    }
    if (ai?.agentFixPrompt) {
      lines.push("Fix prompt (written for this codebase's AI editor — act on it directly):", String(ai.agentFixPrompt), "");
    }
  }

  const filterNote = page.minSeverity && page.minSeverity !== "info" ? ` at ${page.minSeverity} or above` : "";
  if (sorted.length === 0) {
    lines.push(`No findings${filterNote}.`);
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
  if (firstPage && d.compliance?.disclaimer) lines.push("", `Compliance mapping note: ${d.compliance.disclaimer}`);
  return lines.join("\n");
}

/**
 * Exported so the public server card (scripts/build-server-card.ts) is built
 * from these exact tool definitions, and a test can catch the two drifting.
 * Listing tools never touches the user or the request; only calling one does.
 */
export function buildServer(httpReq: Request, user: TokenUser): McpServer {
  const server = new McpServer({ name: "secscan", version: "1.1.0" }, { instructions: SERVER_INSTRUCTIONS });

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

  // ── Account ──────────────────────────────────────────────────────────────

  server.registerTool(
    "get_account",
    {
      title: "Scans left and plan",
      description:
        "How many scans the user can still run — free scans, plan scans and credits — and their plan. " +
        "Check this before starting several scans.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const { status, body } = await runAppRoute(checkoutRouter, "get", "/billing/status", httpReq, user);
      if (status >= 400) return text(String(body?.error ?? "Could not read the account."), true);
      return text(formatAccount(body));
    },
  );

  // ── Domain verification ──────────────────────────────────────────────────

  server.registerTool(
    "start_domain_verification",
    {
      title: "Start verifying a domain",
      description:
        "Begin proving the user owns a domain, which unlocks active tests (injection, XSS, SSRF, access control) on its scans. " +
        "Returns a file to publish on the site, or a DNS TXT record — an editor can usually add the file to the codebase " +
        "and deploy it. Then call check_domain_verification. Calling it again returns the same token, so a record already published stays valid.",
      inputSchema: { domain: z.string().min(1).max(253).describe("The domain, e.g. example.com or https://example.com") },
      annotations: { idempotentHint: false },
    },
    async ({ domain }) => {
      const { status, body } = await runAppRoute(domainVerificationRouter, "post", "/domain-verifications", httpReq, user, {
        body: { domain },
      });
      if (status >= 400) return text(String(body?.error ?? "Could not start verification."), true);
      return text(formatVerification(body.verification));
    },
  );

  server.registerTool(
    "check_domain_verification",
    {
      title: "Check a domain verification",
      description:
        "Check whether the file or DNS record from start_domain_verification is live. On success the domain is verified " +
        "and its next scan includes active tests. DNS changes can take a few minutes.",
      inputSchema: { domain: z.string().min(1).max(253).describe("The domain passed to start_domain_verification") },
      annotations: { idempotentHint: true, openWorldHint: true },
    },
    async ({ domain }) => {
      const { status, body } = await runAppRoute(
        domainVerificationRouter,
        "post",
        "/domain-verifications/:domain/check",
        httpReq,
        user,
        { params: { domain: hostOf(domain) } },
      );
      if (status === 409 && body?.verification) {
        return text(`Not found yet. ${body.detail ?? ""}\n\n${formatVerification(body.verification)}`, true);
      }
      if (status >= 400) return text(String(body?.error ?? "Could not check verification."), true);
      return text(formatVerification(body.verification));
    },
  );

  // ── Monitoring ───────────────────────────────────────────────────────────

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

  return server;
}

/** The hostname from "example.com", "https://example.com/path" or similar; the input unchanged if unparseable. */
function hostOf(domain: string): string {
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
    `Credits: ${b.credits}`,
    sub
      ? `Plan: ${sub.plan} (${sub.status}) · ${sub.includedScansRemaining} included scans left this period · ` +
        `up to ${sub.urlLimit} monitored sites` +
        (sub.currentPeriodEnd ? ` · renews ${String(sub.currentPeriodEnd).slice(0, 10)}` : "")
      : "Plan: none",
    b.paymentsEnabled ? `Plans and credits: ${APP_ORIGIN}/settings#billing` : "Buying scans is not open yet.",
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

/**
 * JSON-RPC methods answered without a token: the handshake and the tool list.
 *
 * Directories (Glama, Smithery, the MCP Registry) health-check a server by
 * connecting and listing its tools. With every request behind a token they got
 * a 401, marked the connector "Unhealthy", and a list would not accept it. The
 * tool names and descriptions are already public (server-card.json and
 * secscan.info/ai-editors), so listing them reveals nothing new.
 *
 * Calling a tool is NOT here and never may be: every tools/call still needs a
 * token, because each one reads or spends something that belongs to a user.
 */
const PUBLIC_METHODS = new Set(["initialize", "notifications/initialized", "ping", "tools/list"]);

/**
 * True only when EVERY message in the body is a public method. A batch that
 * slips one tools/call in among public ones is refused whole. Exported for tests.
 */
export function isPublicMcpRequest(body: unknown): boolean {
  const messages = Array.isArray(body) ? body : [body];
  return (
    messages.length > 0 &&
    messages.every(
      (m) =>
        m !== null &&
        typeof m === "object" &&
        typeof (m as { method?: unknown }).method === "string" &&
        PUBLIC_METHODS.has((m as { method: string }).method),
    )
  );
}

/** Tokenless handshakes and tool listings, per IP. A health check makes a few a minute. */
const mcpPublicRateLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60_000, max: 30, label: "minute" }],
  name: "mcp-public",
});

/**
 * Stands in for a user on tokenless requests. It can only ever reach
 * initialize/ping/tools/list (isPublicMcpRequest gates the body), none of
 * which touch the user — the same placeholder serverCard.ts builds with.
 */
const ANONYMOUS = { id: "anonymous", email: null } as never as TokenUser;

async function serve(req: Request, res: Response, server: McpServer): Promise<void> {
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
}

router.post("/mcp", async (req, res): Promise<void> => {
  const user = await authenticateApiToken(req.headers["authorization"]);
  if (!user) {
    if (!isPublicMcpRequest(req.body)) {
      res
        .status(401)
        .setHeader("WWW-Authenticate", 'Bearer realm="secscan"')
        .json({ error: `Missing or invalid API token. Create one at ${APP_ORIGIN}/settings#ai-editors.` });
      return;
    }
    const publicDecision = mcpPublicRateLimit.decide(req);
    if (!publicDecision.allowed) {
      res
        .status(429)
        .setHeader("Retry-After", String(publicDecision.retryAfterSeconds ?? 60))
        .json({ error: "Too many requests. Try again in a minute." });
      return;
    }
    await serve(req, res, buildServer(req, ANONYMOUS));
    return;
  }

  // Per-user request budget, checked after authentication so it counts
  // against the account rather than the address.
  const decision = mcpRateLimit.decide(Object.assign(Object.create(req), { user, isAuthenticated: () => true }) as Request);
  if (!decision.allowed) {
    res
      .status(429)
      .setHeader("Retry-After", String(decision.retryAfterSeconds ?? 60))
      .json({ error: `Too many requests — at most ${decision.rule?.max} per ${decision.rule?.label}. Try again in ${decision.retryAfterSeconds} seconds.` });
    return;
  }

  await serve(req, res, buildServer(req, user));
});

// Stateless: there is no server-initiated stream to open and no session to end.
router.get("/mcp", (_req, res) => {
  res.status(405).setHeader("Allow", "POST").json({ error: "Use POST." });
});
router.delete("/mcp", (_req, res) => {
  res.status(405).setHeader("Allow", "POST").json({ error: "Use POST." });
});

export default router;
