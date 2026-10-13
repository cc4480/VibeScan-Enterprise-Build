import { type IRouter } from "express";
import { LoginBody, attempts, isRateLimited, maskEmail, publicUser, startSession } from "./accountShared";
import { db, usersTable, scansTable, creditsTable, monitorSubscriptionsTable, dismissedFindingsTable, reportSharesTable, domainVerificationsTable, githubInstallationsTable, authTokensTable, pendingLoginsTable, billingSubscriptionsTable, purchaseIntentsTable, apiTokensTable, feedbackTable, findingVerificationsTable, oauthCodesTable, oauthRefreshTokensTable } from "@workspace/db";
import { stripe } from "../lib/stripe";
import { eq } from "drizzle-orm";
import { hashPassword, verifyPassword, needsRehash, dummyHash } from "../lib/password";
import { clearSession, deleteSessionsForUser, getSessionId } from "../lib/auth";
import { LOGIN_CODE_TTL_MS, normalizeLoginCode } from "../lib/loginCode";
import { abandonLoginChallenges, issueLoginChallenge, redeemLoginChallenge } from "../lib/pendingLogin";
import { sendLoginCode } from "../lib/mailer";
import { clientIp } from "../lib/clientIp";

/** Sign-in with an emailed code, sign-out, and deleting the account. */



export function registerAccountSession(router: IRouter): void {
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
        // Spend the same hashing time as a real check, or the reply time says whether the account exists.
        await verifyPassword(password, await dummyHash());
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

      // An account with no address on file cannot receive a code. That should be
      // impossible — registering requires an email — but signing someone in
      // without the second factor because their data is odd is exactly the
      // fallback an attacker would look for, so it refuses instead.
      if (!row.email) {
        req.log.error({ userId: row.id }, "Account has a password but no email — cannot send a sign-in code");
        res.status(500).json({ error: "Could not sign you in" });
        return;
      }

      const { challenge, code } = await issueLoginChallenge(row.id);

      // Deliberately awaited and NOT caught-and-ignored. sendLoginCode throws
      // where the other senders swallow, because here the mail IS the sign-in:
      // reporting success and sending nothing would leave the user at a code
      // prompt they can never satisfy.
      try {
        await sendLoginCode(row.email, code, Math.round(LOGIN_CODE_TTL_MS / 60000));
      } catch (err) {
        // Spend the challenge we just minted. Leaving it live would put a code
        // nobody received into the one-live-challenge slot, so the user's next
        // attempt would silently retire it anyway — but this keeps the table
        // honest about what is outstanding.
        await abandonLoginChallenges(row.id);
        req.log.error({ err }, "Could not send sign-in code");
        res.status(502).json({ error: "Could not send your sign-in code. Please try again shortly." });
        return;
      }

      res.json({
        twoFactorRequired: true,
        challenge,
        // Echoed so the client can show WHERE the code went without having to
        // remember the address the user typed. Masked: this response is the reply
        // to a password, and a full address here would let someone who guessed a
        // password harvest it.
        sentTo: maskEmail(row.email),
      });
    } catch (err) {
      req.log.error({ err }, "Login failed");
      res.status(500).json({ error: "Could not sign you in" });
    }
  });

  // ── Log in (step 2 of 2: emailed code) ───────────────────────────────────────

  router.post("/account/login/verify", async (req, res): Promise<void> => {
    // Keyed on IP as well as capped per challenge. The five-attempt cap is the
    // real defence; this stops a script burning someone else's five as fast as
    // the network allows.
    if (isRateLimited(`login2fa:${clientIp(req)}`)) {
      res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
      return;
    }

    const challenge = typeof req.body?.challenge === "string" ? req.body.challenge : "";
    const code = normalizeLoginCode(req.body?.code);
    if (!challenge || !code) {
      res.status(400).json({ error: "Enter the 6-digit code from your email" });
      return;
    }

    try {
      const result = await redeemLoginChallenge(challenge, code);
      if (!result.ok) {
        // ONE message for every failure. Telling "wrong code" from "no such
        // challenge" would confirm a guessed challenge was real, and "expired"
        // from "wrong" would tell an attacker their timing, not their guess, was
        // the problem. The reason is logged, not sent.
        if (result.reason === "too_many_attempts") {
          req.log.warn("Sign-in code exhausted its attempts — possible brute force");
        }
        res.status(401).json({ error: "That code is not valid. Start again to get a new one." });
        return;
      }

      const [row] = await db.select().from(usersTable).where(eq(usersTable.id, result.userId));
      if (!row) {
        // The account went away between the two steps (deleted mid-login).
        res.status(401).json({ error: "That code is not valid. Start again to get a new one." });
        return;
      }

      await startSession(req, res, row);
      res.json({ user: publicUser(row) });
    } catch (err) {
      req.log.error({ err }, "Sign-in code verification failed");
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

    // Stop the money BEFORE erasing anything. Deleting the rows but leaving a
    // live Stripe subscription would keep charging every month to an account
    // that no longer exists, with no way left to sign in and cancel it. So a
    // subscription that cannot be cancelled blocks the deletion: the account
    // stays intact and the person can retry, or cancel from Settings first.
    try {
      const [plan] = await db
        .select({
          status: billingSubscriptionsTable.status,
          stripeSubscriptionId: billingSubscriptionsTable.stripeSubscriptionId,
        })
        .from(billingSubscriptionsTable)
        .where(eq(billingSubscriptionsTable.userId, userId))
        .limit(1);

      if (plan?.stripeSubscriptionId && plan.status !== "cancelled") {
        if (!stripe) {
          res.status(503).json({
            error: "Your subscription could not be cancelled right now, so nothing was deleted. Please try again shortly.",
          });
          return;
        }
        // Immediate, not at period end: there will be no account left to use
        // the rest of the month. Stripe answers "already canceled" for a
        // subscription cancelled elsewhere, which is the outcome we want.
        try {
          await stripe.subscriptions.cancel(plan.stripeSubscriptionId);
        } catch (err) {
          const code = (err as { code?: string } | null)?.code;
          if (code !== "resource_missing") throw err;
        }
        req.log.info({ userId }, "Cancelled Stripe subscription before account deletion");
      }
    } catch (err) {
      req.log.error({ err, userId }, "Could not cancel subscription; account NOT deleted");
      res.status(502).json({
        error: "Your subscription could not be cancelled, so nothing was deleted. Please try again, or cancel it from Settings first.",
      });
      return;
    }

    try {
      await db.delete(scansTable).where(eq(scansTable.userId, userId));
      await db.delete(monitorSubscriptionsTable).where(eq(monitorSubscriptionsTable.userId, userId));
      await db.delete(reportSharesTable).where(eq(reportSharesTable.userId, userId));
      await db.delete(dismissedFindingsTable).where(eq(dismissedFindingsTable.userId, userId));
      await db.delete(domainVerificationsTable).where(eq(domainVerificationsTable.userId, userId));
      await db.delete(githubInstallationsTable).where(eq(githubInstallationsTable.userId, userId));
      await db.delete(creditsTable).where(eq(creditsTable.userId, userId));
      await db.delete(billingSubscriptionsTable).where(eq(billingSubscriptionsTable.userId, userId));
      // Tokens die with the account: a token outliving it would authenticate as
      // an id that no longer exists (the join in authenticateApiToken would
      // refuse it, but a credential should not survive its owner either way).
      await db.delete(apiTokensTable).where(eq(apiTokensTable.userId, userId));
      await db.delete(purchaseIntentsTable).where(eq(purchaseIntentsTable.userId, userId));
      // Feedback is kept — it is about the product, not the person — but no
      // longer says who sent it.
      await db
        .update(feedbackTable)
        .set({ userId: null, email: null })
        .where(eq(feedbackTable.userId, userId));
      await db.delete(authTokensTable).where(eq(authTokensTable.userId, userId));
      // Tables with no foreign key to users: ids and verdicts only, but still the account's.
      await db.delete(findingVerificationsTable).where(eq(findingVerificationsTable.userId, userId));
      await db.delete(oauthCodesTable).where(eq(oauthCodesTable.userId, userId));
      await db.delete(oauthRefreshTokensTable).where(eq(oauthRefreshTokensTable.userId, userId));
      await db.delete(pendingLoginsTable).where(eq(pendingLoginsTable.userId, userId));
      await db.delete(usersTable).where(eq(usersTable.id, userId));

      // EVERY session, not just this one. getSession reads the session's own JSON
      // snapshot and never re-checks usersTable, so a session on another device
      // kept working for its full 7-day TTL after the account it names was
      // erased: still reading /api/auth/user, still able to start scans that
      // write rows owned by a deleted id, and — because deleting the account
      // deletes its scans — still holding a freshly reset free-scan allowance.
      await deleteSessionsForUser(userId);
      await clearSession(res, getSessionId(req));

      req.log.info({ userId }, "Account deleted at user request");
      res.json({ ok: true });
    } catch (err) {
      req.log.error({ err, userId }, "Failed to delete account");
      res.status(500).json({ error: "Failed to delete account" });
    }
  });

  // ── Email verification ───────────────────────────────────────────────────────

}
