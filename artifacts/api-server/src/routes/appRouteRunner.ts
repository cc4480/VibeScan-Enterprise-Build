/**
 * Running the website's own code on behalf of a token holder.
 *
 * Shared by the MCP server (routes/mcp.ts) and the REST API (routes/v1.ts). Both
 * keep one rule: NO SIDE DOOR. Nothing here launches a scan, charges a credit or
 * changes an account by its own logic; it runs the website's route, with its rate
 * limiters and validation, for the token's user. Reads are scoped to that user in
 * every query.
 */
import type { Request, Response } from "express";
import { db, scansTable, reportsTable } from "@workspace/db";
import { and, eq } from "drizzle-orm";
import type { TokenUser } from "../lib/apiTokens";
import { createScanHandler, scanRateLimit, scanNetworkRateLimit } from "./scans";

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Run the website's scan-launch handler for this user and capture its answer.
 * Only the fields that handler reads are supplied (see createScanHandler).
 */
export async function launchScan(
  httpReq: Request,
  user: TokenUser,
  url: string,
  githubRepo?: string,
): Promise<{ status: number; body: any }> {
  // A request-shaped object carrying the token's user and the REAL client
  // address, so the per-user and per-network limits count against the same
  // buckets as the website — an editor gets no extra allowance.
  const asUser = Object.assign(Object.create(httpReq), {
    user,
    body: { targetUrl: url, ...(githubRepo ? { githubRepoUrl: githubRepo } : {}) },
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

export async function ownScan(userId: string, scanId: string) {
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

export async function reportForScan(userId: string, scanId: string) {
  const [report] = await db
    .select({ id: reportsTable.id, targetUrl: reportsTable.targetUrl, scannedAt: reportsTable.scannedAt, data: reportsTable.data })
    .from(reportsTable)
    .where(and(eq(reportsTable.scanId, scanId), eq(reportsTable.userId, userId)))
    .limit(1);
  return report ?? null;
}
