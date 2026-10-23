import { type IRouter, type Request } from "express";
import { MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH, attempts, isRateLimited, startSession } from "./accountShared";
import { z } from "zod";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { hashPassword, verifyPassword } from "../lib/password";
import { clearSession, deleteSessionsForUser, getSessionId } from "../lib/auth";
import { issueToken, redeemToken } from "../lib/authTokens";
import { abandonLoginChallenges } from "../lib/pendingLogin";
import { sendEmailVerification, sendPasswordReset } from "../lib/mailer";
import { clientIp } from "../lib/clientIp";
import { revokeAllAccess } from "../lib/oauthTokens";
import { APP_ORIGIN } from "../lib/appOrigin";

/** Email verification and password forgot / reset / change. */



export function registerAccountRecovery(router: IRouter): void {
  function appOrigin(): string {
    // In production an unset APP_ORIGIN falls back to the product's own origin: a relative link in a
    // reset email goes nowhere. Development keeps it empty so links point at the local server.
    const configured = process.env["APP_ORIGIN"] ?? (process.env["NODE_ENV"] === "production" ? APP_ORIGIN : "");
    return configured.replace(/\/+$/, "");
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
    // Per ADDRESS as well as per IP: every request here that finds an account mails
    // it a reset link, so rotating addresses must not be able to mail one person
    // without limit. Applied before the lookup, so it says nothing about the address.
    if (isRateLimited(`forgot-email:${parsed.data.email}`)) {
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
      // Sessions are not the only way in: someone who had the old password may have minted an
      // API token or connected an app, and those would survive the reset.
      await revokeAllAccess(result.userId);
      await clearSession(res, getSessionId(req));

      // And kill any pending two-factor challenge. Someone who knew the OLD
      // password could be holding a live challenge from seconds ago; without
      // this, resetting the password would evict their sessions while leaving
      // them one emailed code away from a fresh one.
      await abandonLoginChallenges(result.userId);

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

      // As on reset: someone holding the old password may have minted an API token
      // or connected an app, and changing the password must cut those off too.
      await revokeAllAccess(row.id);

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
}
