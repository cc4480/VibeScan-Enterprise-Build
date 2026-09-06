/**
 * Email preferences: the Settings toggle for product updates, and the
 * one-click unsubscribe target named in the List-Unsubscribe header on
 * recurring alert mail.
 *
 * Account mail — password resets, email verification, purchase receipts — is
 * deliberately not covered by either. Letting someone switch those off would
 * lock them out of their own account and hide what they were charged.
 */
import { Router, type IRouter } from "express";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { verifyUnsubscribeToken } from "../lib/emailPrefs";
import { setMarketingSubscription } from "../lib/mailer";

const router: IRouter = Router();

router.get("/account/email-preferences", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const [row] = await db
      .select({
        marketingOptedOut: usersTable.marketingOptedOut,
        alertEmailsOptedOut: usersTable.alertEmailsOptedOut,
      })
      .from(usersTable)
      .where(eq(usersTable.id, req.user.id));

    res.json({
      productUpdates: !row?.marketingOptedOut,
      monitorAlerts: !row?.alertEmailsOptedOut,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to read email preferences");
    res.status(500).json({ error: "Failed to read email preferences" });
  }
});

router.put("/account/email-preferences", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const { productUpdates, monitorAlerts } = req.body ?? {};
  if (typeof productUpdates !== "boolean" && typeof monitorAlerts !== "boolean") {
    res.status(400).json({ error: "productUpdates or monitorAlerts (boolean) is required" });
    return;
  }

  try {
    const changes: Record<string, boolean> = {};
    if (typeof productUpdates === "boolean") changes["marketingOptedOut"] = !productUpdates;
    if (typeof monitorAlerts === "boolean") changes["alertEmailsOptedOut"] = !monitorAlerts;

    const [row] = await db
      .update(usersTable)
      .set(changes)
      .where(eq(usersTable.id, req.user.id))
      .returning({
        email: usersTable.email,
        marketingOptedOut: usersTable.marketingOptedOut,
        alertEmailsOptedOut: usersTable.alertEmailsOptedOut,
      });

    // The audience is the list a broadcast actually sends to, so a preference
    // that only lived in our database would be silently ignored the moment an
    // update went out from Resend. Not awaited into the response: the toggle
    // has already been saved, and a Resend hiccup should not make the user
    // think it failed.
    if (typeof productUpdates === "boolean" && row?.email) {
      void setMarketingSubscription(row.email, productUpdates);
    }

    res.json({
      productUpdates: !row?.marketingOptedOut,
      monitorAlerts: !row?.alertEmailsOptedOut,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to update email preferences");
    res.status(500).json({ error: "Failed to update email preferences" });
  }
});

/**
 * One-click unsubscribe (RFC 8058).
 *
 * POST because that is what the standard requires and what Gmail and Yahoo
 * send when someone uses their native unsubscribe control. It must act
 * immediately, with no confirmation step and no sign-in — the mail client
 * calls it directly, and the signed token in the URL is the authorisation.
 */
router.post("/email/unsubscribe", async (req, res): Promise<void> => {
  const token = String(req.query["token"] ?? req.body?.token ?? "");
  const userId = verifyUnsubscribeToken(token);
  if (!userId) {
    res.status(400).json({ error: "Invalid or expired unsubscribe link" });
    return;
  }

  try {
    await db
      .update(usersTable)
      .set({ alertEmailsOptedOut: true })
      .where(eq(usersTable.id, userId));
    req.log.info({ userId }, "Unsubscribed from alert emails via List-Unsubscribe");
    res.json({ ok: true });
  } catch (err) {
    req.log.error({ err, userId }, "Failed to process unsubscribe");
    res.status(500).json({ error: "Could not process the unsubscribe" });
  }
});

/**
 * The human-visible version, for someone who clicks the link in a client that
 * renders it rather than using a native control. Same effect, but it answers
 * with a page instead of JSON.
 */
router.get("/email/unsubscribe", async (req, res): Promise<void> => {
  const userId = verifyUnsubscribeToken(String(req.query["token"] ?? ""));

  const page = (title: string, message: string) =>
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="robots" content="noindex">' +
    `<title>${title}</title></head>` +
    '<body style="font-family:system-ui,-apple-system,sans-serif;background:#0f1117;color:#e4e4e7;' +
    'display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">' +
    '<main style="text-align:center;padding:2rem;max-width:32rem">' +
    `<h1 style="font-size:1.25rem;margin:0 0 .5rem">${title}</h1>` +
    `<p style="color:#a1a1aa;font-size:.875rem;margin:0 0 1.25rem;line-height:1.6">${message}</p>` +
    '<a href="/monitor" style="color:#34d399;font-size:.875rem">Manage your monitors</a>' +
    "</main></body></html>";

  if (!userId) {
    res
      .status(400)
      .type("html")
      .send(page("Link not valid", "This unsubscribe link could not be verified. It may have been altered in transit."));
    return;
  }

  try {
    await db
      .update(usersTable)
      .set({ alertEmailsOptedOut: true })
      .where(eq(usersTable.id, userId));
    req.log.info({ userId }, "Unsubscribed from alert emails via link");
    res
      .type("html")
      .send(
        page(
          "Unsubscribed",
          "You will no longer receive monitor alert emails — CVE matches, regressions and certificate expiry warnings. " +
            "Account emails such as password resets and receipts still send. You can turn alerts back on in Settings.",
        ),
      );
  } catch (err) {
    req.log.error({ err, userId }, "Failed to process unsubscribe");
    res.status(500).type("html").send(page("Something went wrong", "Please try again, or email us and we will sort it out."));
  }
});

export default router;
