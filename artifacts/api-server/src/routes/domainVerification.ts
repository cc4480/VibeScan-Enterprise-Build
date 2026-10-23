/**
 * Domain-ownership verification: the flow that unlocks active offensive
 * probing for a domain. See lib/activeProbeGate.ts for what it unlocks and
 * lib/domainVerify.ts for what counts as proof.
 *
 * Three endpoints: list what the caller has, start a challenge for a domain,
 * and check whether the challenge has been satisfied.
 */
import { Router, type IRouter } from "express";
import { db, domainVerificationsTable } from "@workspace/db";
import { and, desc, eq } from "drizzle-orm";
import { isRateLimited } from "./accountShared";
import {
  WELL_KNOWN_PATH,
  extractDomain,
  generateVerificationToken,
  isVerificationCurrent,
  runVerificationCheck,
  txtRecordName,
  verificationExpiresAt,
} from "../lib/domainVerify";

const router: IRouter = Router();

/**
 * Shapes one row for the client, including the instructions to satisfy it.
 *
 * `verified` means the verification is valid NOW, the same answer the
 * active-probe gate gives, not merely that it once passed. `verifiedAt` is the
 * last time the proof was seen and `expiresAt` the date it lapses unless it is
 * seen again; the daily re-check (lib/domainReverify.ts) keeps moving both
 * forward while the proof stays in place. A lapsed row keeps its token, so the
 * user can republish the proof and press Check.
 */
function present(row: typeof domainVerificationsTable.$inferSelect) {
  return {
    domain: row.domain,
    verified: isVerificationCurrent(row.verifiedAt),
    verifiedAt: row.verifiedAt,
    expiresAt: row.verifiedAt ? verificationExpiresAt(row.verifiedAt) : null,
    method: row.method,
    token: row.token,
    dns: { name: txtRecordName(row.domain), type: "TXT", value: row.token },
    wellKnown: { url: `https://${row.domain}${WELL_KNOWN_PATH}`, content: row.token },
  };
}

router.get("/domain-verifications", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const rows = await db
      .select()
      .from(domainVerificationsTable)
      .where(eq(domainVerificationsTable.userId, req.user.id))
      .orderBy(desc(domainVerificationsTable.createdAt));

    res.json({ verifications: rows.map(present) });
  } catch (err) {
    req.log.error({ err }, "Failed to list domain verifications");
    res.status(500).json({ error: "Failed to list domain verifications" });
  }
});

router.post("/domain-verifications", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  let domain: string;
  try {
    domain = extractDomain(String(req.body?.domain ?? ""));
    if (!domain) throw new Error("empty");
  } catch {
    res.status(400).json({ error: "A valid domain is required" });
    return;
  }

  try {
    // Hand back an existing row untouched, verified or not. Re-issuing for a
    // verified domain would revoke access the user already has; re-issuing for
    // a pending one silently invalidates the TXT record or file they may have
    // just published — clicking "verify" twice, or an editor calling
    // start_domain_verification again, left the published code stale and the
    // check failing with no hint why. The token proves nothing until it is
    // published, so keeping it costs no security.
    const [existing] = await db
      .select()
      .from(domainVerificationsTable)
      .where(
        and(
          eq(domainVerificationsTable.userId, req.user.id),
          eq(domainVerificationsTable.domain, domain),
        ),
      );
    if (existing) {
      res.json({ verification: present(existing) });
      return;
    }

    const token = generateVerificationToken();
    const [row] = await db
      .insert(domainVerificationsTable)
      .values({ userId: req.user.id, domain, token })
      // Two requests racing past the check above: the loser gets the winner's
      // row back unchanged (a no-op update, so RETURNING still yields it).
      .onConflictDoUpdate({
        target: [domainVerificationsTable.userId, domainVerificationsTable.domain],
        set: { domain },
      })
      .returning();

    res.status(201).json({ verification: present(row) });
  } catch (err) {
    req.log.error({ err, domain }, "Failed to start domain verification");
    res.status(500).json({ error: "Failed to start domain verification" });
  }
});

router.post("/domain-verifications/:domain/check", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  // Each check makes the server fetch a URL on someone's site, so it is limited per account.
  if (isRateLimited(`domain-check:${req.user.id}`)) {
    res.status(429).json({ error: "Too many checks. Please wait a few minutes and try again." });
    return;
  }

  let domain: string;
  try {
    domain = extractDomain(req.params.domain);
  } catch {
    res.status(400).json({ error: "A valid domain is required" });
    return;
  }

  try {
    const [row] = await db
      .select()
      .from(domainVerificationsTable)
      .where(
        and(
          eq(domainVerificationsTable.userId, req.user.id),
          eq(domainVerificationsTable.domain, domain),
        ),
      );

    if (!row) {
      res.status(404).json({ error: "No verification started for that domain" });
      return;
    }
    // Only a verification that is still valid short-circuits. A lapsed one runs
    // the check again, and passing it sets verifiedAt to now, which is how a
    // user whose proof had been removed gets back in.
    if (isVerificationCurrent(row.verifiedAt)) {
      res.json({ verification: present(row) });
      return;
    }

    const method = await runVerificationCheck(domain, row.token);

    const now = new Date();
    const [updated] = await db
      .update(domainVerificationsTable)
      .set({
        lastCheckedAt: now,
        ...(method ? { method, verifiedAt: now } : {}),
      })
      .where(eq(domainVerificationsTable.id, row.id))
      .returning();

    if (!method) {
      res.status(409).json({
        error: "Verification not found yet",
        detail:
          `Publish either a TXT record at ${txtRecordName(domain)} with the token, ` +
          `or the token at https://${domain}${WELL_KNOWN_PATH}, then check again. ` +
          "DNS changes can take a few minutes to propagate.",
        verification: present(updated),
      });
      return;
    }

    req.log.info({ domain, method, userId: req.user.id }, "Domain ownership verified");
    res.json({ verification: present(updated) });
  } catch (err) {
    req.log.error({ err, domain }, "Failed to check domain verification");
    res.status(500).json({ error: "Failed to check domain verification" });
  }
});

export default router;
