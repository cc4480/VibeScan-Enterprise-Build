import { Router, type IRouter, type Request } from "express";
import { db, scansTable, reportsTable, usersTable } from "@workspace/db";
import { eq, and, desc, inArray, gte, count } from "drizzle-orm";
import {
  CreateScanBody,
  ListScansResponseItem,
  GetScanStatusResponse,
} from "@workspace/api-zod";
import { enqueueScan } from "../lib/queue";
import { validateCredentials, encryptCredentials } from "../lib/scanCredentials";
import { checkUrlSafe } from "../lib/ssrfGuard";

// ── Abuse and cost control ───────────────────────────────────────────────────
// A scan is expensive in a way an API request normally is not: it launches a
// browser and runs sustained outbound traffic for minutes. Before this, the
// only limit was worker concurrency, which throttles how fast the queue drains
// rather than how much anyone may put on it.
//
// Two limits, because they stop different things. The burst limiter is
// in-memory and per-instance, matching the limiter in routes/auth.ts — enough
// to stop a hot loop, and it resets on deploy. The daily quota is counted in
// Postgres, so it holds across replicas and restarts, which is what actually
// bounds cost.

const BURST_WINDOW_MS = 60_000;
const BURST_MAX = Number(process.env["SCAN_BURST_LIMIT"] ?? 5);
const DAILY_MAX_ANON = Number(process.env["SCAN_DAILY_LIMIT_ANON"] ?? 10);
const DAILY_MAX_ACCOUNT = Number(process.env["SCAN_DAILY_LIMIT_ACCOUNT"] ?? 50);

const burst = new Map<string, number[]>();

function clientIp(req: Request): string {
  return String(
    req.headers["x-forwarded-for"] ?? req.socket.remoteAddress ?? "unknown",
  ).split(",")[0]!.trim();
}

function isBurstLimited(key: string): boolean {
  const now = Date.now();
  const recent = (burst.get(key) ?? []).filter((t) => now - t < BURST_WINDOW_MS);
  recent.push(now);
  burst.set(key, recent);
  // Keep the map from growing without bound on a long-lived process.
  if (burst.size > 10_000) {
    for (const [k, times] of burst) {
      if (times.every((t) => now - t >= BURST_WINDOW_MS)) burst.delete(k);
    }
  }
  return recent.length > BURST_MAX;
}

/** Scans this user has started in the last 24 hours. */
async function scansToday(userId: string): Promise<number> {
  const since = new Date(Date.now() - 24 * 60 * 60_000);
  const [row] = await db
    .select({ n: count() })
    .from(scansTable)
    .where(and(eq(scansTable.userId, userId), gte(scansTable.createdAt, since)));
  return row?.n ?? 0;
}

const router: IRouter = Router();

const STATUS_PROGRESS: Record<string, number> = {
  pending: 0,
  paid: 10,
  queued: 20,
  scanning: 55,
  analyzing: 80,
  complete: 100,
  failed: 0,
};

router.get("/scans", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const scans = await db
      .select()
      .from(scansTable)
      .where(eq(scansTable.userId, req.user.id))
      .orderBy(desc(scansTable.createdAt));

    // Batch-fetch reports for all complete scans to avoid N+1
    const completeScanIds = scans
      .filter((s) => s.status === "complete")
      .map((s) => s.id);

    const reports =
      completeScanIds.length > 0
        ? await db
            .select({ id: reportsTable.id, scanId: reportsTable.scanId })
            .from(reportsTable)
            .where(inArray(reportsTable.scanId, completeScanIds))
        : [];

    const reportByScanId = new Map(reports.map((r) => [r.scanId, r.id]));

    res.json(
      scans.map((s) =>
        ListScansResponseItem.parse({
          id: s.id,
          userId: s.userId,
          userEmail: s.userEmail,
          targetUrl: s.targetUrl,
          tier: s.tier,
          status: s.status,
          stripeSessionId: s.stripeSessionId ?? null,
          stripePaymentIntentId: s.stripePaymentIntentId ?? null,
          createdAt: s.createdAt,
          startedAt: s.startedAt ?? null,
          completedAt: s.completedAt ?? null,
          error: s.error ?? null,
          reportId: s.status === "complete" ? (reportByScanId.get(s.id) ?? null) : null,
        }),
      ),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to list scans");
    res.status(500).json({ error: "Failed to list scans" });
  }
});

router.post("/scans", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  if (isBurstLimited(`scan:${clientIp(req)}`)) {
    res.status(429).json({
      error: "Too many scans started at once. Wait a minute and try again.",
    });
    return;
  }

  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { targetUrl, tier, credentials, secondaryCredentials } = parsed.data;

  // Credit packs are not supported in the free tier
  if (tier === "pack_5" || tier === "pack_20") {
    res.status(400).json({ error: "Credit packs are not available." });
    return;
  }

  try {
    const parsedUrl = new URL(targetUrl);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      throw new Error("bad protocol");
    }
  } catch {
    res.status(400).json({ error: "Invalid URL. Must start with http:// or https://" });
    return;
  }

  // Refuse targets that point back at our own network before anything is
  // stored or queued. The scanner enforces this again on every request it
  // makes — this check exists so the person gets a straight answer now rather
  // than an empty report later, and so an abusive target never reaches the
  // queue at all.
  const addressCheck = await checkUrlSafe(targetUrl, { allowOptOut: true });
  if (!addressCheck.ok) {
    req.log.warn({ targetUrl, reason: addressCheck.reason }, "Blocked scan target");
    res.status(400).json({
      error:
        "That address cannot be scanned: it is a private, local or link-local " +
        "address. Scan a publicly reachable URL instead.",
    });
    return;
  }

  // ── Credentials for an authenticated scan ──────────────────────────────────
  // Validated before the scan is queued so a bad login is reported now rather
  // than as a mysteriously empty report later. Encrypted immediately; the
  // plaintext never reaches the database or the job payload.
  let credentialsEncrypted: string | null = null;
  let secondaryCredentialsEncrypted: string | null = null;
  let credentialsAuthorizedAt: Date | null = null;

  if (credentials) {
    // A credentialed scan means holding a customer's live login. An anonymous
    // identity is a UUID in localStorage, auto-accepted on sight — no password,
    // no second factor, nothing to revoke — so anyone who copies that string
    // becomes the user and inherits the stored credential. Storing a production
    // password against that is not a risk worth taking for the convenience of
    // skipping registration, so credentials require a real, verified account.
    // Anonymous users keep full access to unauthenticated scanning.
    const [account] = await db
      .select({
        passwordHash: usersTable.passwordHash,
        emailVerifiedAt: usersTable.emailVerifiedAt,
      })
      .from(usersTable)
      .where(eq(usersTable.id, req.user.id))
      .limit(1);

    if (!account?.passwordHash) {
      res.status(403).json({
        error:
          "Authenticated scanning needs a registered account. Create one to " +
          "store login details for a scan — your existing scans stay with you.",
      });
      return;
    }

    if (!account.emailVerifiedAt) {
      res.status(403).json({
        error:
          "Verify your email address before storing login details for a scan.",
      });
      return;
    }

    const check = validateCredentials(credentials);
    if (!check.ok) {
      res.status(400).json({ error: check.error });
      return;
    }
    credentialsEncrypted = encryptCredentials(credentials);
    credentialsAuthorizedAt = new Date();
    // Logged without the credentials themselves — see the redaction list in
    // lib/logger.ts.
    req.log.info({ mode: credentials.mode }, "Credentialed scan requested");

    // A second account unlocks access-control testing. It is only meaningful
    // alongside the first — comparing one account against nothing proves
    // nothing about authorisation between users.
    if (secondaryCredentials) {
      const secondCheck = validateCredentials(secondaryCredentials);
      if (!secondCheck.ok) {
        res.status(400).json({ error: `Second account: ${secondCheck.error}` });
        return;
      }
      secondaryCredentialsEncrypted = encryptCredentials(secondaryCredentials);
      req.log.info("Access-control testing enabled — second account supplied");
    }
  } else if (secondaryCredentials) {
    res.status(400).json({
      error: "A second account only works alongside a first one. Add primary credentials too.",
    });
    return;
  }

  // Registered accounts get the higher allowance: they are attributable and
  // recoverable in a way an anonymous UUID is not.
  const [quotaRow] = await db
    .select({ passwordHash: usersTable.passwordHash })
    .from(usersTable)
    .where(eq(usersTable.id, req.user.id))
    .limit(1);
  const dailyMax = quotaRow?.passwordHash ? DAILY_MAX_ACCOUNT : DAILY_MAX_ANON;

  if ((await scansToday(req.user.id)) >= dailyMax) {
    res.status(429).json({
      error: quotaRow?.passwordHash
        ? `Daily scan limit reached (${dailyMax}). It resets 24 hours after each scan.`
        : `Daily scan limit reached (${dailyMax}). Create an account for a higher limit.`,
    });
    return;
  }

  const [scan] = await db
    .insert(scansTable)
    .values({
      userId: req.user.id,
      userEmail: req.user.email ?? "",
      targetUrl,
      tier,
      status: "paid",
      credentialsEncrypted,
      secondaryCredentialsEncrypted,
      credentialsAuthorizedAt,
    })
    .returning();

  await enqueueScan({ scanId: scan.id, userId: req.user.id, targetUrl, tier });

  await db
    .update(scansTable)
    .set({ status: "queued", startedAt: new Date() })
    .where(eq(scansTable.id, scan.id));

  res.status(201).json({ scanId: scan.id, checkoutUrl: null, creditUsed: false });
});

router.get("/scans/:id/status", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  const [scan] = await db
    .select()
    .from(scansTable)
    .where(and(eq(scansTable.id, rawId), eq(scansTable.userId, req.user.id)));

  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  let reportId: string | null = null;
  let grade: string | null = null;
  if (scan.status === "complete") {
    const [report] = await db
      .select({ id: reportsTable.id, data: reportsTable.data })
      .from(reportsTable)
      .where(eq(reportsTable.scanId, scan.id));
    reportId = report?.id ?? null;
    const reportData = report?.data as { summary?: { grade?: string } } | undefined;
    grade = reportData?.summary?.grade ?? null;
  }

  res.json(
    GetScanStatusResponse.parse({
      id: scan.id,
      targetUrl: scan.targetUrl,
      tier: scan.tier,
      status: scan.status,
      progress: STATUS_PROGRESS[scan.status] ?? 0,
      createdAt: scan.createdAt,
      startedAt: scan.startedAt ?? null,
      completedAt: scan.completedAt ?? null,
      error: scan.error ?? null,
      reportId,
      grade,
    }),
  );
});

export default router;
