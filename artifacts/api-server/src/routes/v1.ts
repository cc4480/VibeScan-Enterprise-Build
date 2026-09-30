/**
 * The REST API, version 1: scan a URL and read the result from a script or CI job.
 *
 *   curl -X POST https://secscan.us/api/v1/scans \
 *     -H "Authorization: Bearer ssk_…" -H "Content-Type: application/json" \
 *     -d '{"url":"https://staging.example.com"}'
 *
 * Authenticated by a token whose scope is "api" (Settings → API). An "mcp" token is
 * refused here and an "api" token is refused by the MCP endpoint.
 *
 * Same rule as the MCP server, and for the same reason: NO SIDE DOOR. A scan is
 * launched by the website's own handler, after its own rate limiters, so the free
 * allowance, credits and plan scans, the SSRF guard and the ownership gate for
 * active tests apply exactly as they do in the browser (routes/appRouteRunner.ts).
 * Reads are scoped to the token's owner in every query, and another user's scan is
 * a 404, never a 403.
 *
 * Errors are always { "error": { "code", "message" } } so a client can branch on
 * the code and show the message.
 */
import { Router, type IRouter, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { db, scansTable } from "@workspace/db";
import { and, desc, eq, ne } from "drizzle-orm";
import { authenticateApiToken, type TokenUser } from "../lib/apiTokens";
import { APP_ORIGIN } from "../lib/appOrigin";
import { rateLimitMiddleware } from "../lib/rateLimit";
import { launchScan, ownScan, reportForScan, UUID } from "./appRouteRunner";
import { API_V1_SPEC } from "../lib/apiV1Spec";
import { summariseReport } from "../lib/apiV1Report";
import { toSarif } from "../lib/sarif";
import { changesForReport } from "../lib/scanDiffLoader";

const router: IRouter = Router();

const FINISHED = new Set(["complete", "failed"]);
const MAX_WAIT_SECONDS = 60;
/** A wait holds a connection and polls the database; a client firing many at once must not pin them. */
const MAX_CONCURRENT_WAITS = 3;
const activeWaits = new Map<string, number>();

const v1RateLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60_000, max: 120, label: "minute" }],
  name: "api-v1",
  keyFrom: (req) => (req.isAuthenticated() ? `v1:${req.user.id}` : undefined),
});

function fail(res: Response, status: number, code: string, message: string): void {
  res.status(status).json({ error: { code, message } });
}

/** The website's own error, mapped to a stable code. */
function codeFor(status: number): string {
  if (status === 400) return "invalid_request";
  if (status === 401) return "unauthorized";
  if (status === 402) return "payment_required";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limited";
  return status >= 500 ? "server_error" : "error";
}

type Authed = Request & { apiUser: TokenUser };

async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const user = await authenticateApiToken(req.headers["authorization"], "api");
  if (!user) {
    res.setHeader("WWW-Authenticate", 'Bearer realm="secscan-api"');
    fail(res, 401, "unauthorized", `Missing or invalid API token. Create one at ${APP_ORIGIN}/settings (scope: API).`);
    return;
  }
  const asUser = Object.assign(Object.create(req), { user, isAuthenticated: () => true }) as Request;
  const decision = v1RateLimit.decide(asUser);
  if (!decision.allowed) {
    res.setHeader("Retry-After", String(decision.retryAfterSeconds ?? 60));
    fail(res, 429, "rate_limited", `At most ${decision.rule?.max} requests per ${decision.rule?.label}. Try again in ${decision.retryAfterSeconds} seconds.`);
    return;
  }
  (req as Authed).apiUser = user;
  next();
}

const ScanBody = z.object({ url: z.string().trim().min(1).max(2048), githubRepo: z.string().max(300).optional() });

// The spec is public: it describes the API and names no one's data.
router.get("/v1/openapi.json", (_req, res) => {
  res.json(API_V1_SPEC);
});

router.get("/v1/me", authenticate, (req, res) => {
  const user = (req as Authed).apiUser;
  res.json({ email: user.email, firstName: user.firstName, lastName: user.lastName });
});

router.post("/v1/scans", authenticate, async (req, res): Promise<void> => {
  const parsed = ScanBody.safeParse(req.body);
  if (!parsed.success) {
    fail(res, 400, "invalid_request", 'Send a JSON body like {"url": "https://example.com"}.');
    return;
  }
  const user = (req as Authed).apiUser;
  const result = await launchScan(req, user, parsed.data.url, parsed.data.githubRepo);
  if (result.status >= 400 || !result.body?.scanId) {
    fail(res, result.status >= 400 ? result.status : 502, codeFor(result.status), String(result.body?.error ?? "The scan could not be started."));
    return;
  }
  res.status(202).json({
    id: result.body.scanId,
    status: "queued",
    url: parsed.data.url,
    paidWith: result.body.paidWith ?? null,
    links: { self: `${APP_ORIGIN}/api/v1/scans/${result.body.scanId}` },
  });
});

router.get("/v1/scans", authenticate, async (req, res): Promise<void> => {
  const user = (req as Authed).apiUser;
  const limit = Math.min(Math.max(Number.parseInt(String(req.query["limit"] ?? "20"), 10) || 20, 1), 50);
  const rows = await db
    .select({ id: scansTable.id, url: scansTable.targetUrl, status: scansTable.status, createdAt: scansTable.createdAt, completedAt: scansTable.completedAt })
    .from(scansTable)
    // Re-checks of a single finding (origin "verify") are not scans the person asked for; they appear on the finding.
    .where(and(eq(scansTable.userId, user.id), ne(scansTable.origin, "verify")))
    .orderBy(desc(scansTable.createdAt))
    .limit(limit);
  res.json({ scans: rows });
});

router.get("/v1/scans/:id", authenticate, async (req, res): Promise<void> => {
  const user = (req as Authed).apiUser;
  const id = String(req.params["id"]);
  if (!UUID.test(id)) {
    fail(res, 404, "not_found", "No scan with that id.");
    return;
  }

  // ?wait=N holds the request until the scan finishes or N seconds pass (max 60),
  // so a CI job can call once instead of polling. Past the concurrency cap the
  // call still answers, immediately, with the current status.
  const asked = Math.min(Math.max(Number.parseInt(String(req.query["wait"] ?? "0"), 10) || 0, 0), MAX_WAIT_SECONDS);
  const inFlight = activeWaits.get(user.id) ?? 0;
  const mayWait = asked > 0 && inFlight < MAX_CONCURRENT_WAITS;
  const deadline = Date.now() + (mayWait ? asked * 1000 : 0);
  if (mayWait) activeWaits.set(user.id, inFlight + 1);
  let scan = await ownScan(user.id, id);
  try {
    while (scan && !FINISHED.has(scan.status) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 2000));
      scan = await ownScan(user.id, id);
    }
  } finally {
    if (mayWait) {
      const left = (activeWaits.get(user.id) ?? 1) - 1;
      if (left <= 0) activeWaits.delete(user.id);
      else activeWaits.set(user.id, left);
    }
  }
  if (!scan) {
    fail(res, 404, "not_found", "No scan with that id.");
    return;
  }

  const base = { id: scan.id, url: scan.targetUrl, status: scan.status, error: scan.error ?? null, createdAt: scan.createdAt, completedAt: scan.completedAt };
  if (scan.status !== "complete") {
    res.json(base);
    return;
  }
  const report = await reportForScan(user.id, scan.id);
  // Counts only here; the lists are in the report. A failed comparison leaves the field out.
  const changes = report ? await changesForReport(user.id, { scanId: scan.id, targetUrl: report.targetUrl, scannedAt: report.scannedAt, data: report.data }).catch(() => null) : null;
  res.json({
    ...base,
    ...(report ? summariseReport(report.data) : {}),
    ...(changes ? { changes: { since: changes.since, new: changes.added.length + changes.firstSeen.length, fixed: changes.fixed.length, notRechecked: changes.notRechecked.length, unchanged: changes.unchanged } } : {}),
    links: { report: `${APP_ORIGIN}/api/v1/scans/${scan.id}/report`, web: report ? `${APP_ORIGIN}/report/${report.id}` : null } });
});

router.get("/v1/scans/:id/report", authenticate, async (req, res): Promise<void> => {
  const user = (req as Authed).apiUser;
  const id = String(req.params["id"]);
  const scan = UUID.test(id) ? await ownScan(user.id, id) : null;
  if (!scan) {
    fail(res, 404, "not_found", "No scan with that id.");
    return;
  }
  if (scan.status !== "complete") {
    fail(res, 409, "not_ready", `That scan is ${scan.status}, not finished yet.`);
    return;
  }
  const report = await reportForScan(user.id, scan.id);
  if (!report) {
    fail(res, 409, "not_ready", "The report is still being saved. Try again in a moment.");
    return;
  }
  const changes = await changesForReport(user.id, { scanId: scan.id, targetUrl: report.targetUrl, scannedAt: report.scannedAt, data: report.data }).catch(() => null);
  res.json({ id: scan.id, url: report.targetUrl, scannedAt: report.scannedAt, report: report.data, ...(changes ? { changes } : {}) });
});

// The same findings as SARIF 2.1.0, for GitHub code scanning and other CI tools.
router.get("/v1/scans/:id/sarif", authenticate, async (req, res): Promise<void> => {
  const user = (req as Authed).apiUser;
  const id = String(req.params["id"]);
  const scan = UUID.test(id) ? await ownScan(user.id, id) : null;
  if (!scan) {
    fail(res, 404, "not_found", "No scan with that id.");
    return;
  }
  const report = scan.status === "complete" ? await reportForScan(user.id, scan.id) : null;
  if (!report) {
    fail(res, 409, "not_ready", `That scan is ${scan.status === "complete" ? "still being saved" : scan.status}, not ready yet.`);
    return;
  }
  res.type("application/sarif+json").send(JSON.stringify(toSarif({ targetUrl: report.targetUrl, scannedAt: report.scannedAt, data: report.data })));
});

// Any other /v1 path: the same error shape, so a client never has to parse an HTML 404.
router.use("/v1", (_req, res) => fail(res, 404, "not_found", "No such endpoint. See /api/v1/openapi.json."));

export default router;
