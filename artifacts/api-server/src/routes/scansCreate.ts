/** The scan-creation handler shared by POST /api/scans and the /api/v1 API. */
import { type Request, type Response } from "express";
import { db, scansTable, usersTable } from "@workspace/db";
import { eq, and, gte, count } from "drizzle-orm";
import { CreateScanBody } from "@workspace/api-zod";
import { normaliseGithubRepoInput } from "../lib/githubRepoInput";
import { repoOnlyAddress } from "../lib/repoOnlyScan";
import { parseGithubRepoRef } from "../lib/githubSourceProbe";
import { installationForRepo } from "../lib/githubInstallationAccess";
import { linkedInstallationIds } from "../lib/githubLinks";
import { enqueueScan } from "../lib/queue";
import { prepareScanCredentials } from "./scansCredentials";
import { checkScanTarget } from "../lib/ssrfGuard";
import { TRIAL_LIMIT_MESSAGE, TRIAL_LIMIT_CODE, TrialExhaustedError, DailyLimitError, insertScanRow } from "../lib/freeTrial";
import { refundFailedScan, chargeScan, refundCharge } from "../lib/billing";
import { zodMessage } from "../lib/zodMessage";

// ── Abuse and cost control ───────────────────────────────────────────────────
// A scan is expensive in a way an API request normally is not: it launches a
// browser and runs sustained outbound traffic for minutes. Worker concurrency
// throttles how fast the queue drains, not how much anyone may put on it.
//
// Two limits, because they stop different things.
//
// The sliding window in lib/rateLimit.ts stops a burst. It is in-process, so it
// resets on deploy and each replica counts separately — fine for the thing it
// is for, which is a hot loop rather than a patient attacker.
//
// The daily quota below is counted in Postgres, so it survives restarts and
// holds across replicas. That is what actually bounds cost, and it is why the
// two coexist rather than one replacing the other.

export const DAILY_MAX_ANON = Number(process.env["SCAN_DAILY_LIMIT_ANON"] ?? 10);

export const DAILY_MAX_ACCOUNT = Number(process.env["SCAN_DAILY_LIMIT_ACCOUNT"] ?? 50);

/** Scans this user has started in the last 24 hours. */
export async function scansToday(userId: string): Promise<number> {
  const since = new Date(Date.now() - 24 * 60 * 60_000);
  const [row] = await db
    .select({ n: count() })
    .from(scansTable)
    .where(and(eq(scansTable.userId, userId), gte(scansTable.createdAt, since)));
  return row?.n ?? 0;
}

/**
 * Launch a scan. Exported so the MCP endpoint (routes/mcp.ts) runs EXACTLY this
 * — the same trial, payment, SSRF, ownership and validation rules — rather than
 * a copy that could drift from what the website enforces. It reads only
 * req.user, req.body, req.isAuthenticated and req.log.
 */
export async function createScanHandler(req: Request, res: Response): Promise<void> {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: zodMessage(parsed.error) });
    return;
  }

  // A GitHub repository address where the website goes is a scan of that repository alone (lib/repoOnlyScan.ts):
  // the repository is the target, there is no site to log in to, and any repository field or login sent is ignored.
  const repoOnly = repoOnlyAddress(parsed.data.targetUrl);
  const targetUrl = repoOnly ?? parsed.data.targetUrl;
  const credentials = repoOnly ? undefined : parsed.data.credentials;
  const secondaryCredentials = repoOnly ? undefined : parsed.data.secondaryCredentials;

  // Checked before anything is charged: a mistyped repository should be a plain 400, not a refund.
  const repoInput = repoOnly ? ({ ok: true, url: repoOnly } as const) : normaliseGithubRepoInput(parsed.data.githubRepoUrl);
  if (!repoInput.ok) {
    res.status(400).json({ error: repoInput.error });
    return;
  }
  const githubRepoUrl = repoInput.url;

  // Whether this scan may read the repository through the GitHub App (a private repository its owner shared).
  // Decided here from the signed-in account and GitHub's own answer, never from anything in the request body:
  // an installation id is not a secret, so accepting one would let any user name someone else's. Null, which is
  // also the answer to every doubt or failure, leaves the scan reading only what is public.
  const repoRef = githubRepoUrl ? parseGithubRepoRef(githubRepoUrl) : null;
  const githubInstallationId = repoRef
    ? await installationForRepo({
        email: req.user.email,
        repo: { owner: repoRef.owner, repo: repoRef.repo },
        linked: await linkedInstallationIds(req.user.id),
      })
    : null;

  // The automatic second account tests a login against a new account, so it means nothing without
  // one. Said plainly rather than silently dropped: an API caller who set it expects it to happen.
  // (A supplied second account makes it unnecessary, so it is simply not used in that case.)
  if (!repoOnly && parsed.data.autoSecondAccount === true && !credentials) {
    res.status(400).json({ error: "autoSecondAccount needs credentials: it creates the second account to compare with the first." });
    return;
  }
  const autoSecondAccount = !repoOnly && parsed.data.autoSecondAccount === true && !secondaryCredentials;

  // Free scans first, then paid credits. Spending a credit while free scans
  // remain would charge someone for something they already had.
  //
  // The credit is taken here, before the scan row exists, because the
  // alternative — validate, create, then charge — leaves a window in which a
  // scan exists that nobody paid for. The cost of taking it first is that every
  // rejection below has to give it back, which is what refundIfCharged is for.
  // Spend order (free trial, then the plan's included scans, then credits)
  // lives in one place — chargeScan — shared with the MCP endpoint and the
  // Monitor page, so no way in can price a scan differently.
  const paidWith = await chargeScan(req.user.id);
  if (paidWith === null) {
    res.status(403).json({ error: TRIAL_LIMIT_MESSAGE, code: TRIAL_LIMIT_CODE });
    return;
  }
  if (paidWith !== "free") req.log.info({ paidWith }, "Scan paid for");
  const creditUsed = paidWith === "credit";

  /** Give back what this request took, to the place it came from. */
  const refundIfCharged = async (): Promise<void> => {
    if (paidWith === "free") return;
    try {
      await refundCharge(req.user.id, paidWith);
      req.log.info({ paidWith }, "Scan payment refunded — scan was not created");
    } catch (err) {
      // Worth a loud log rather than a 500: the caller's request already
      // failed for its own reason, and burying that under a refund error
      // would report the wrong problem.
      req.log.error({ err, paidWith }, "Could not refund a rejected scan");
    }
  };

  // There is one kind of scan now: the full one. The request schema still
  // accepts "deep" so existing clients keep working, and ignores it either way.
  // Scans recorded before the tier was retired keep whatever they ran as,
  // because a stored record should say what actually happened.
  const tier = "deep" as const;

  // Refuse targets that point back at our own network before anything is
  // stored or queued. The scanner runs inside our network and quotes responses
  // back in the report, so an unguarded target URL is an open proxy into it.
  // lib/http.ts enforces this again on every request and every redirect hop —
  // this check exists so the person gets a straight answer now rather than an
  // empty report later, and so an abusive target never reaches the queue.
  //
  // One call, not two: this was checkScanTarget twice in a row, and because the
  // first returned on failure with the guard's terse internal reason, the
  // plain-English message below was unreachable.
  const targetCheck = await checkScanTarget(targetUrl);
  if (!targetCheck.ok) {
    req.log.warn({ targetUrl, reason: targetCheck.reason }, "Blocked scan target");
    await refundIfCharged();
    res.status(400).json({
      error:
        targetCheck.reason === "not a valid URL" ||
        targetCheck.reason === "must use http or https"
          ? "That does not look like a URL we can scan. Use a full http:// or https:// address."
          : "That address cannot be scanned: it is a private, local or link-local " +
            "address. Scan a publicly reachable URL instead.",
    });
    return;
  }

  // The stored logins, checked and encrypted before the scan is queued (scansCredentials.ts).
  const prepared = await prepareScanCredentials(req.user.id, credentials, secondaryCredentials, req.log);
  if (!prepared.ok) {
    await refundIfCharged();
    res.status(prepared.status).json({ error: prepared.error });
    return;
  }
  const { credentialsEncrypted, secondaryCredentialsEncrypted, credentialsAuthorizedAt } = prepared;

  // Registered accounts get the higher allowance: they are attributable and
  // recoverable in a way an anonymous UUID is not.
  const [quotaRow] = await db
    .select({ passwordHash: usersTable.passwordHash })
    .from(usersTable)
    .where(eq(usersTable.id, req.user.id))
    .limit(1);
  const dailyMax = quotaRow?.passwordHash ? DAILY_MAX_ACCOUNT : DAILY_MAX_ANON;

  if ((await scansToday(req.user.id)) >= dailyMax) {
    await refundIfCharged();
    res.status(429).json({
      error: quotaRow?.passwordHash
        ? `Daily scan limit reached (${dailyMax}). It resets 24 hours after each scan.`
        : `Daily scan limit reached (${dailyMax}). Create an account for a higher limit.`,
    });
    return;
  }

  let scan: typeof scansTable.$inferSelect;
  try {
    scan = await insertScanRow({
      userId: req.user.id,
      userEmail: req.user.email ?? "",
      targetUrl,
      tier,
      status: "paid",
      credentialsEncrypted,
      secondaryCredentialsEncrypted,
      credentialsAuthorizedAt,
      githubRepoUrl,
      githubInstallationId: githubInstallationId === null ? null : String(githubInstallationId),
      autoSecondAccount,
      // Recorded so a scan that fails later is refunded to the same place.
      paidWith,
    }, { dailyMax });
  } catch (err) {
    // Requests that arrived together with this one used up the daily limit.
    if (err instanceof DailyLimitError) {
      await refundIfCharged();
      res.status(429).json({
        error: quotaRow?.passwordHash
          ? `Daily scan limit reached (${dailyMax}). It resets 24 hours after each scan.`
          : `Daily scan limit reached (${dailyMax}). Create an account for a higher limit.`,
      });
      return;
    }
    // The free scans were used up by requests that arrived together with this one.
    if (err instanceof TrialExhaustedError) {
      res.status(403).json({ error: TRIAL_LIMIT_MESSAGE, code: TRIAL_LIMIT_CODE });
      return;
    }
    // Paid for, not created: give it back before failing the request.
    req.log.error({ err }, "Could not create the scan row");
    await refundIfCharged();
    res.status(500).json({ error: "Could not start the scan. You were not charged — please try again." });
    return;
  }

  try {
    await enqueueScan({ scanId: scan.id, userId: req.user.id, targetUrl, tier });
  } catch (err) {
    // The row exists and is paid for but will never run. Fail it and refund
    // through the same exactly-once path the worker uses.
    req.log.error({ err, scanId: scan.id }, "Could not queue the scan");
    // It will never run, so the stored logins are discarded now rather than kept for nothing.
    await db
      .update(scansTable)
      .set({ status: "failed", error: "Could not be queued", credentialsEncrypted: null, secondaryCredentialsEncrypted: null })
      .where(eq(scansTable.id, scan.id));
    await refundFailedScan(scan.id).catch((e) => req.log.error({ err: e, scanId: scan.id }, "Refund after queue failure failed"));
    res.status(503).json({ error: "Could not start the scan. You were not charged — please try again." });
    return;
  }

  await db
    .update(scansTable)
    .set({ status: "queued", startedAt: new Date() })
    .where(eq(scansTable.id, scan.id));

  res.status(201).json({ scanId: scan.id, checkoutUrl: null, creditUsed, paidWith });
}
