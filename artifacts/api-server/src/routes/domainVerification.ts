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
import {
  WELL_KNOWN_PATH,
  checkTxtRecord,
  checkWellKnownFile,
  extractDomain,
  generateVerificationToken,
  txtRecordName,
} from "../lib/domainVerify";

const router: IRouter = Router();

/** Shapes one row for the client, including the instructions to satisfy it. */
function present(row: typeof domainVerificationsTable.$inferSelect) {
  return {
    domain: row.domain,
    verified: row.verifiedAt != null,
    verifiedAt: row.verifiedAt,
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
    // Re-issuing for an already-verified domain would revoke access the user
    // already has, so hand back the existing row untouched instead.
    const [existing] = await db
      .select()
      .from(domainVerificationsTable)
      .where(
        and(
          eq(domainVerificationsTable.userId, req.user.id),
          eq(domainVerificationsTable.domain, domain),
        ),
      );
    if (existing?.verifiedAt) {
      res.json({ verification: present(existing) });
      return;
    }

    const token = generateVerificationToken();
    const [row] = await db
      .insert(domainVerificationsTable)
      .values({ userId: req.user.id, domain, token })
      .onConflictDoUpdate({
        target: [domainVerificationsTable.userId, domainVerificationsTable.domain],
        set: { token, method: null, lastCheckedAt: null },
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
    if (row.verifiedAt) {
      res.json({ verification: present(row) });
      return;
    }

    // DNS first: it is cheaper than an HTTP round trip and cannot be satisfied
    // by anyone who merely controls a path on the web server.
    const method = (await checkTxtRecord(domain, row.token))
      ? "dns"
      : (await checkWellKnownFile(domain, row.token))
        ? "well_known"
        : null;

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
