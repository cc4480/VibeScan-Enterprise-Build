import { type IRouter } from "express";
import { isRateLimited, maskEmail } from "./accountShared";
import { db, scansTable, creditsTable, monitorSubscriptionsTable, dismissedFindingsTable, reportsTable, reportSharesTable, reportBadgesTable, domainVerificationsTable, githubInstallationsTable, authTokensTable, pendingLoginsTable, pendingRegistrationsTable, billingSubscriptionsTable, purchaseIntentsTable, apiTokensTable, feedbackTable, findingVerificationsTable, teamMembersTable, trustPagesTable, githubIssuesTable, githubIssueDestinationsTable, ticketsTable, ticketDestinationsTable, oauthCodesTable, oauthRefreshTokensTable, usersTable } from "@workspace/db";
import { stripe } from "../lib/stripe";
import { eq, or } from "drizzle-orm";
import { clearSession, deleteSessionsForUser, getSessionId } from "../lib/auth";
import { LOGIN_CODE_TTL_MS, normalizeLoginCode } from "../lib/loginCode";
import { abandonLoginChallenges, issueLoginChallenge, redeemLoginChallenge } from "../lib/pendingLogin";
import { sendLoginCode } from "../lib/mailer";
import { clientIp } from "../lib/clientIp";
import { carryTrialUsage } from "../lib/freeTrial";

/** Deleting the account: an emailed code first, then the erase itself. */
export function registerAccountDelete(router: IRouter): void {
  /**
   * Step one of deleting an account: mail a code to the address on file. A session alone is not
   * enough to erase everything (a borrowed laptop, a stolen cookie), so the delete below also
   * needs the code. Works for password and Google accounts alike, since both have an inbox.
   */
  router.post("/account/delete/code", async (req, res): Promise<void> => {
    if (!req.isAuthenticated()) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    if (!req.user.email) {
      res.status(400).json({ error: "This account has no email address to send a code to." });
      return;
    }
    if (isRateLimited(`delcode:${req.user.id}`)) {
      res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
      return;
    }
    const { challenge, code } = await issueLoginChallenge(req.user.id);
    try {
      await sendLoginCode(req.user.email, code, Math.round(LOGIN_CODE_TTL_MS / 60000));
    } catch (err) {
      await abandonLoginChallenges(req.user.id);
      req.log.error({ err }, "Could not send account deletion code");
      res.status(502).json({ error: "Could not send your code. Please try again shortly." });
      return;
    }
    res.json({ challenge, sentTo: maskEmail(req.user.email) });
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

    // The emailed code proves whoever holds this session can also read the account's mail. An
    // account with no address (a legacy anonymous one) has nothing to send to and is let through.
    if (req.user.email) {
      if (isRateLimited(`delete:${clientIp(req)}`)) {
        res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
        return;
      }
      const challenge = typeof req.body?.challenge === "string" ? req.body.challenge : "";
      const code = normalizeLoginCode(req.body?.code);
      const redeemed = challenge && code ? await redeemLoginChallenge(challenge, code) : null;
      if (!redeemed?.ok || redeemed.userId !== userId) {
        res.status(403).json({ error: "Enter the 6-digit code we emailed you to delete your account.", code: "delete_code_required" });
        return;
      }
    }

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
      // One transaction: a failure part-way must not leave a half-erased account (the subscription is
      // already cancelled by now, so the retry has to be able to finish the job).
      // DELETE LIST RULE: every table with a column holding the account's user id
      // must be named here, because there are no foreign keys to users and so no
      // cascade will reach it. Adding a table with a user-id column means adding a
      // delete here. The integration test (accountDelete.integration.test.ts)
      // derives the table list from the schema and fails if one is missing, so
      // the list cannot silently fall behind. The exception is feedback, which is
      // anonymised rather than deleted.
      await db.transaction(async (tx) => {
        // Before the scans go: remembers this month's free scans already used, so registering again
        // at the same address does not reset the allowance (lib/freeTrial.ts).
        await carryTrialUsage(tx, userId, req.user.email);
        await tx.delete(scansTable).where(eq(scansTable.userId, userId));
        await tx.delete(monitorSubscriptionsTable).where(eq(monitorSubscriptionsTable.userId, userId));
        // Reports and their badges and shares carry their own user id, and a report whose scan was
        // never recorded (scan_id null) is not reached by the cascade from scans, so each is named.
        await tx.delete(reportBadgesTable).where(eq(reportBadgesTable.userId, userId));
        await tx.delete(reportSharesTable).where(eq(reportSharesTable.userId, userId));
        await tx.delete(reportsTable).where(eq(reportsTable.userId, userId));
        await tx.delete(dismissedFindingsTable).where(eq(dismissedFindingsTable.userId, userId));
        await tx.delete(domainVerificationsTable).where(eq(domainVerificationsTable.userId, userId));
        await tx.delete(githubInstallationsTable).where(eq(githubInstallationsTable.userId, userId));
        await tx.delete(creditsTable).where(eq(creditsTable.userId, userId));
        await tx.delete(billingSubscriptionsTable).where(eq(billingSubscriptionsTable.userId, userId));
        // Tokens die with the account: a token outliving it would authenticate as
        // an id that no longer exists (the join in authenticateApiToken would
        // refuse it, but a credential should not survive its owner either way).
        await tx.delete(apiTokensTable).where(eq(apiTokensTable.userId, userId));
        await tx.delete(purchaseIntentsTable).where(eq(purchaseIntentsTable.userId, userId));
        // Feedback is kept — it is about the product, not the person — but no
        // longer says who sent it.
        await tx
          .update(feedbackTable)
          .set({ userId: null, email: null })
          .where(eq(feedbackTable.userId, userId));
        await tx.delete(authTokensTable).where(eq(authTokensTable.userId, userId));
        // Tables with no foreign key to users: ids and verdicts only, but still the account's.
        await tx.delete(findingVerificationsTable).where(eq(findingVerificationsTable.userId, userId));
        // Teams: the account's own team (as owner) and every team it was on (as a teammate). A teammate's access ends here.
        await tx.delete(teamMembersTable).where(or(eq(teamMembersTable.userId, userId), eq(teamMembersTable.memberId, userId)));
        await tx.delete(trustPagesTable).where(eq(trustPagesTable.userId, userId));
        await tx.delete(githubIssuesTable).where(eq(githubIssuesTable.userId, userId));
        await tx.delete(githubIssueDestinationsTable).where(eq(githubIssueDestinationsTable.userId, userId));
        await tx.delete(ticketsTable).where(eq(ticketsTable.userId, userId));
        await tx.delete(ticketDestinationsTable).where(eq(ticketDestinationsTable.userId, userId));
        await tx.delete(oauthCodesTable).where(eq(oauthCodesTable.userId, userId));
        await tx.delete(oauthRefreshTokensTable).where(eq(oauthRefreshTokensTable.userId, userId));
        await tx.delete(pendingLoginsTable).where(eq(pendingLoginsTable.userId, userId));
        // A sign-up started from this anonymous identity; its promotion target is gone with the account.
        await tx.delete(pendingRegistrationsTable).where(eq(pendingRegistrationsTable.anonUserId, userId));
        await tx.delete(usersTable).where(eq(usersTable.id, userId));
      });

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
}
