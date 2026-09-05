/**
 * Email + password accounts.
 *
 * Phase 01 of moving off the anonymous-identity model. Until now a user was a
 * UUID their browser generated and stored in localStorage, sent as a bearer
 * token — which meant scan history died with the browser profile, and there was
 * nowhere safe to keep anything sensitive on a user's behalf.
 *
 * Registering while holding one of those anonymous tokens converts that same
 * row into an account in place. The id never changes, so every scan, report,
 * credit and monitor subscription already pointing at it comes along without
 * migrating a single row — and the bearer token stops working the moment the
 * row has a password (see middlewares/authMiddleware.ts).
 */

import { Router, type IRouter, type Request } from "express";
import { z } from "zod";
import {
  db,
  usersTable,
  scansTable,
  creditsTable,
  monitorSubscriptionsTable,
  dismissedFindingsTable,
  reportSharesTable,
  domainVerificationsTable,
} from "@workspace/db";
import { eq } from "drizzle-orm";
import { hashPassword, verifyPassword, needsRehash } from "../lib/password";
import {
  createSession,
  clearSession,
  deleteSessionsForUser,
  getSessionId,
  SESSION_COOKIE,
  SESSION_TTL,
} from "../lib/auth";
import { issueToken, redeemToken } from "../lib/authTokens";
import { sendEmailVerification, sendPasswordReset, addToMarketingAudience, sendWelcomeEmail } from "../lib/mailer";
import { clientIp } from "../lib/clientIp";

const router: IRouter = Router();

// Deliberately no composition rules (no "must contain a symbol"). Length is
// what actually resists guessing, and the rest mostly pushes people toward
// Password1! and a sticky note.
const MIN_PASSWORD_LENGTH = 10;
const MAX_PASSWORD_LENGTH = 200;

const RegisterBody = z.object({
  email: z.string().trim().toLowerCase().email("Enter a valid email address"),
  password: z
    .string()
    .min(MIN_PASSWORD_LENGTH, `Use at least ${MIN_PASSWORD_LENGTH} characters`)
    .max(MAX_PASSWORD_LENGTH, "That password is too long"),
});

const LoginBody = z.object({
  email: z.string().trim().toLowerCase().email("Enter a valid email address"),
  password: z.string().min(1, "Enter your password"),
});

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ── Rate limiting ────────────────────────────────────────────────────────────
// Same shape as the limiter already in routes/auth.ts. In-memory, so it resets
// on deploy and is per-instance; adequate against online guessing, and not a
// substitute for the scrypt cost that protects a stolen table.
const attempts = new Map<string, number[]>();
const WINDOW_MS = 15 * 60_000;
const MAX_ATTEMPTS = 10;

function isRateLimited(key: string): boolean {
  const now = Date.now();
  const recent = (attempts.get(key) ?? []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  attempts.set(key, recent);
  return recent.length > MAX_ATTEMPTS;
}

function publicUser(row: typeof usersTable.$inferSelect) {
  return {
    id: row.id,
    email: row.email,
    firstName: row.firstName,
    lastName: row.lastName,
    profileImageUrl: row.profileImageUrl,
  };
}

async function startSession(req: Request, res: Parameters<Parameters<IRouter["post"]>[1]>[1], row: typeof usersTable.$inferSelect) {
  const sid = await createSession({
    user: publicUser(row),
    // The OIDC path stores a provider access token here. Password sessions have
    // no upstream token, so this field is unused for them.
    access_token: "",
  });

  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: SESSION_TTL,
    // req.protocol reflects X-Forwarded-Proto only when TRUST_PROXY is set —
    // see the note in app.ts.
    secure: req.protocol === "https",
    path: "/",
  });
}

// ── Register ─────────────────────────────────────────────────────────────────

router.post("/account/register", async (req, res): Promise<void> => {
  if (isRateLimited(`register:${clientIp(req)}`)) {
    res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
    return;
  }

  const parsed = RegisterBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join(", ") });
    return;
  }
  const { email, password } = parsed.data;

  try {
    const [existing] = await db.select().from(usersTable).where(eq(usersTable.email, email));
    if (existing) {
      res.status(409).json({ error: "An account with that email already exists" });
      return;
    }

    const passwordHash = await hashPassword(password);

    // If the caller is holding an anonymous identity, promote that row rather
    // than creating a second one — otherwise their existing scans are stranded
    // on an id they can no longer authenticate as.
    const bearer = req.headers["authorization"]?.startsWith("Bearer ")
      ? req.headers["authorization"].slice(7).trim()
      : undefined;

    let row: typeof usersTable.$inferSelect | undefined;

    if (bearer && UUID_V4.test(bearer)) {
      const [anon] = await db.select().from(usersTable).where(eq(usersTable.id, bearer));
      // Only claim a row that is genuinely anonymous: no password and no email.
      if (anon && !anon.passwordHash && !anon.email) {
        [row] = await db
          .update(usersTable)
          .set({ email, passwordHash })
          .where(eq(usersTable.id, anon.id))
          .returning();
      }
    }

    if (!row) {
      [row] = await db.insert(usersTable).values({ email, passwordHash }).returning();
    }

    if (!row) {
      res.status(500).json({ error: "Could not create the account" });
      return;
    }

    // Best-effort, fire-and-forget: a marketing-audience hiccup must never
    // block or fail account creation. Each function logs and swallows its
    // own errors. `email` (not row.email) because RegisterBody guarantees it
    // non-null here, where the column type alone does not.
    void addToMarketingAudience(email);
    void sendWelcomeEmail(email);

    await startSession(req, res, row);
    res.status(201).json({ user: publicUser(row) });
  } catch (err) {
    req.log.error({ err }, "Registration failed");
    res.status(500).json({ error: "Could not create the account" });
  }
});

// ── Log in ───────────────────────────────────────────────────────────────────

router.post("/account/login", async (req, res): Promise<void> => {
  if (isRateLimited(`login:${clientIp(req)}`)) {
    res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
    return;
  }

  const parsed = LoginBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join(", ") });
    return;
  }
  const { email, password } = parsed.data;

  // One message for every failure below — a distinct "no such account" reply
  // would turn this endpoint into a way to test whether an address is
  // registered.
  const reject = () => res.status(401).json({ error: "Email or password is incorrect" });

  try {
    const [row] = await db.select().from(usersTable).where(eq(usersTable.email, email));
    if (!row?.passwordHash) {
      reject();
      return;
    }

    if (!(await verifyPassword(password, row.passwordHash))) {
      reject();
      return;
    }

    // Upgrade a hash written under weaker parameters, now that the password is
    // in hand and known correct.
    if (needsRehash(row.passwordHash)) {
      const upgraded = await hashPassword(password);
      await db.update(usersTable).set({ passwordHash: upgraded }).where(eq(usersTable.id, row.id));
    }

    await startSession(req, res, row);
    res.json({ user: publicUser(row) });
  } catch (err) {
    req.log.error({ err }, "Login failed");
    res.status(500).json({ error: "Could not sign you in" });
  }
});

// ── Log out ──────────────────────────────────────────────────────────────────

router.post("/account/logout", async (req, res): Promise<void> => {
  // Deleting the session row is what actually revokes it; clearing the cookie
  // alone would leave a stolen copy working until it expired.
  await clearSession(res, getSessionId(req));
  res.json({ ok: true });
});

/**
 * Erase the account and everything belonging to it.
 *
 * Required by GDPR Art. 17 and the CCPA, but the reason to implement it
 * properly rather than flag a row as deleted is simpler: someone asking to be
 * erased means it.
 *
 * Order matters. scans and monitor subscriptions cascade to the rows that hang
 * off them — reports, share links, out-of-band tokens, CVE alerts, score
 * history, regressions, certificate warnings — so those go first and the rest
 * follow. The user row is last, so a failure part-way leaves an account that
 * can still sign in and retry rather than an orphaned set of records with no
 * owner.
 *
 * What survives is named in the privacy policy: Stripe keeps its own payment
 * records for accounting, and database backups age out on their own schedule.
 */
router.delete("/account", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const userId = req.user.id;

  try {
    await db.delete(scansTable).where(eq(scansTable.userId, userId));
    await db.delete(monitorSubscriptionsTable).where(eq(monitorSubscriptionsTable.userId, userId));
    await db.delete(reportSharesTable).where(eq(reportSharesTable.userId, userId));
    await db.delete(dismissedFindingsTable).where(eq(dismissedFindingsTable.userId, userId));
    await db.delete(domainVerificationsTable).where(eq(domainVerificationsTable.userId, userId));
    await db.delete(creditsTable).where(eq(creditsTable.userId, userId));
    await db.delete(usersTable).where(eq(usersTable.id, userId));

    // The session outlives the row it points at unless it is revoked here.
    await clearSession(res, getSessionId(req));

    req.log.info({ userId }, "Account deleted at user request");
    res.json({ ok: true });
  } catch (err) {
    req.log.error({ err, userId }, "Failed to delete account");
    res.status(500).json({ error: "Failed to delete account" });
  }
});

// ── Email verification ───────────────────────────────────────────────────────

function appOrigin(): string {
  return (process.env["APP_ORIGIN"] ?? "").replace(/\/+$/, "");
}

router.post("/account/verify/request", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  if (isRateLimited(`verify:${req.user.id}`)) {
    res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
    return;
  }

  try {
    const [row] = await db.select().from(usersTable).where(eq(usersTable.id, req.user.id));
    if (!row?.email) {
      res.status(400).json({ error: "Add an email address to your account first" });
      return;
    }
    if (row.emailVerifiedAt) {
      res.json({ ok: true, alreadyVerified: true });
      return;
    }

    const token = await issueToken(row.id, "email_verify");
    await sendEmailVerification(row.email, `${appOrigin()}/verify-email?token=${token}`);
    res.json({ ok: true, alreadyVerified: false });
  } catch (err) {
    req.log.error({ err }, "Could not send verification email");
    res.status(500).json({ error: "Could not send the verification email" });
  }
});

router.post("/account/verify", async (req, res): Promise<void> => {
  const token = typeof req.body?.token === "string" ? req.body.token : "";

  try {
    const result = await redeemToken(token, "email_verify");
    if (!result.ok || !result.userId) {
      // One message for expired, spent and never-existed alike — telling them
      // apart reveals whether a guessed token was ever real.
      req.log.info({ reason: result.reason }, "Email verification rejected");
      res.status(400).json({ error: "That link is no longer valid. Request a new one." });
      return;
    }

    await db
      .update(usersTable)
      .set({ emailVerifiedAt: new Date() })
      .where(eq(usersTable.id, result.userId));

    res.json({ ok: true });
  } catch (err) {
    req.log.error({ err }, "Email verification failed");
    res.status(500).json({ error: "Could not verify the email address" });
  }
});

// ── Password reset ───────────────────────────────────────────────────────────

router.post("/account/password/forgot", async (req, res): Promise<void> => {
  const parsed = z
    .object({ email: z.string().trim().toLowerCase().email() })
    .safeParse(req.body);

  // Always the same reply, whether or not the address exists — otherwise this
  // endpoint becomes a way to discover who has an account. Malformed input is
  // answered identically for the same reason.
  const generic = () =>
    res.json({ ok: true, message: "If that email has an account, a reset link is on its way." });

  if (!parsed.success) {
    generic();
    return;
  }
  if (isRateLimited(`forgot:${clientIp(req)}`)) {
    res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
    return;
  }

  try {
    const [row] = await db.select().from(usersTable).where(eq(usersTable.email, parsed.data.email));
    // Only accounts get reset links; an anonymous row has no password to reset.
    if (row?.passwordHash && row.email) {
      const token = await issueToken(row.id, "password_reset");
      await sendPasswordReset(row.email, `${appOrigin()}/reset-password?token=${token}`);
    }
    generic();
  } catch (err) {
    req.log.error({ err }, "Password reset request failed");
    generic();
  }
});

router.post("/account/password/reset", async (req, res): Promise<void> => {
  const parsed = z
    .object({
      token: z.string().min(1),
      password: z
        .string()
        .min(MIN_PASSWORD_LENGTH, `Use at least ${MIN_PASSWORD_LENGTH} characters`)
        .max(MAX_PASSWORD_LENGTH, "That password is too long"),
    })
    .safeParse(req.body);

  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join(", ") });
    return;
  }

  try {
    const result = await redeemToken(parsed.data.token, "password_reset");
    if (!result.ok || !result.userId) {
      req.log.info({ reason: result.reason }, "Password reset rejected");
      res.status(400).json({ error: "That link is no longer valid. Request a new one." });
      return;
    }

    const passwordHash = await hashPassword(parsed.data.password);
    await db
      .update(usersTable)
      .set({ passwordHash })
      .where(eq(usersTable.id, result.userId));

    // Evict every existing session. Whoever prompted the reset may already be
    // signed in, and leaving their cookie alive would make the reset pointless.
    await deleteSessionsForUser(result.userId);
    await clearSession(res, getSessionId(req));

    res.json({ ok: true });
  } catch (err) {
    req.log.error({ err }, "Password reset failed");
    res.status(500).json({ error: "Could not reset the password" });
  }
});

// ── Change password (signed in) ──────────────────────────────────────────────

router.post("/account/password/change", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = z
    .object({
      currentPassword: z.string().min(1, "Enter your current password"),
      newPassword: z
        .string()
        .min(MIN_PASSWORD_LENGTH, `Use at least ${MIN_PASSWORD_LENGTH} characters`)
        .max(MAX_PASSWORD_LENGTH, "That password is too long"),
    })
    .safeParse(req.body);

  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join(", ") });
    return;
  }

  if (isRateLimited(`change:${req.user.id}`)) {
    res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
    return;
  }

  try {
    const [row] = await db.select().from(usersTable).where(eq(usersTable.id, req.user.id));
    if (!row?.passwordHash) {
      res.status(400).json({ error: "This account doesn't have a password set" });
      return;
    }

    // Requiring the current password stops a borrowed session from locking the
    // real owner out of their account.
    if (!(await verifyPassword(parsed.data.currentPassword, row.passwordHash))) {
      res.status(401).json({ error: "Your current password is incorrect" });
      return;
    }

    const passwordHash = await hashPassword(parsed.data.newPassword);
    await db.update(usersTable).set({ passwordHash }).where(eq(usersTable.id, row.id));

    // Sign other devices out, then re-establish the session for this one so the
    // user is not logged out of the page they are standing on.
    await deleteSessionsForUser(row.id);
    await startSession(req, res, { ...row, passwordHash });

    res.json({ ok: true });
  } catch (err) {
    req.log.error({ err }, "Password change failed");
    res.status(500).json({ error: "Could not change the password" });
  }
});

export default router;
