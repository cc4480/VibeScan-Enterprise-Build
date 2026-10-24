/** Marketing audience membership and lifecycle emails. */
import { AUTH_FROM_EMAIL, APP_ORIGIN } from "./appOrigin";
import { isSuppressed } from "./emailSuppression";
import { RESEND_AUDIENCES_API, RESEND_API, resendBody } from "./mailerCore";
import { sendAccountMessage, buildAccountHtml, buildAccountText } from "./mailerAccount";
import { fairUseText } from "./fairUse";

// ── Marketing: shared audience + welcome email ──────────────────────────────
//
// SecScan and Secscan.us run the same engine under two names and share one
// signup pool. Every new account — on either domain, through either sign-in
// path — is added to one Resend Audience so a single broadcast reaches
// everyone, and gets one welcome email. There is no separate opt-in checkbox:
// consent comes from the account ToS, and every future marketing send goes
// through Resend's Audience unsubscribe link, not this one-time message.
//
// Resend restricts per-domain sending keys from managing audiences/contacts
// (a 401 "restricted_api_key" otherwise), so this uses a separate, broader
// key set on both deployments specifically for this — RESEND_API_KEY is left
// alone and keeps its narrower, per-send scope.

/**
 * Mirror a product-updates preference onto the Resend contact.
 *
 * The audience is what a broadcast actually sends to, so a preference held
 * only in our own database would be ignored the moment an update went out
 * from the Resend dashboard. Patches by email rather than by contact id, so
 * it works without storing Resend ids alongside ours.
 *
 * Best-effort: the caller has already saved the preference, so a failure here
 * is logged rather than surfaced. The two can drift if Resend is down, which
 * is worth reconciling if this ever matters at volume.
 */
export async function setMarketingSubscription(email: string, subscribed: boolean): Promise<void> {
  const apiKey = process.env.RESEND_AUDIENCE_API_KEY;
  const audienceId = process.env.RESEND_AUDIENCE_ID;
  if (!apiKey || !audienceId) {
    console.warn("[mailer] Audience not configured — cannot sync product-updates preference");
    return;
  }

  try {
    const res = await fetch(
      `${RESEND_AUDIENCES_API}/${audienceId}/contacts/${encodeURIComponent(email)}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({ unsubscribed: !subscribed }),
      },
    );
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`Resend API ${res.status}: ${errText}`);
    }
    console.log("[mailer] Synced product-updates preference", { email, subscribed });
  } catch (err) {
    console.error("[mailer] Failed to sync product-updates preference:", err);
  }
}

export async function addToMarketingAudience(email: string, firstName?: string | null): Promise<void> {
  const apiKey = process.env.RESEND_AUDIENCE_API_KEY;
  const audienceId = process.env.RESEND_AUDIENCE_ID;
  if (!apiKey || !audienceId) {
    console.warn("[mailer] RESEND_AUDIENCE_API_KEY or RESEND_AUDIENCE_ID not set — skipping audience signup");
    return;
  }

  try {
    const res = await fetch(`${RESEND_AUDIENCES_API}/${audienceId}/contacts`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        email,
        first_name: firstName || undefined,
        unsubscribed: false,
      }),
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`Resend API ${res.status}: ${errText}`);
    }
    console.log("[mailer] Added to marketing audience", { email });
  } catch (err) {
    console.error("[mailer] Failed to add contact to marketing audience:", err);
  }
}

export async function sendWelcomeEmail(toEmail: string, firstName?: string | null): Promise<void> {
  await sendAccountMessage(
    toEmail,
    "Welcome to SecScan.us",
    {
      heading: firstName ? `Welcome, ${firstName}` : "Welcome to SecScan",
      body: "SecScan runs real vulnerability checks, not a checklist: SQL injection, exposed secrets, misconfigured databases, and more. We'll email you when there's something worth knowing: new features, security research, and the occasional product update. Account and security emails (password resets, scan reports) always go out regardless.",
      ctaLabel: "Run your first scan",
      ctaUrl: `${APP_ORIGIN}/dashboard`,
      footnote: "You can unsubscribe from product updates at any time via the link included in those emails.",
    },
    "welcome email",
  );
}

/**
 * "You can buy now" — the email promised to everyone who clicked "Email me when
 * I can buy scans" before checkout existed (routes/purchaseIntent.ts).
 *
 * Returns what happened instead of swallowing it, unlike the other senders
 * here: scripts/notify-purchase-intents.ts marks a person as notified only on
 * "sent", so a missing API key or a Resend outage leaves them on the list for
 * the next run rather than silently breaking the promise.
 *
 * Suppression uses the BULK rule: they asked for this, but it is an
 * announcement, so someone who marked our mail as spam is not sent it.
 */
export async function sendPaymentsLiveEmail(toEmail: string): Promise<"sent" | "suppressed" | "failed"> {
  if (await isSuppressed(toEmail, "bulk")) return "suppressed";
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return "failed";

  const heading = "You can keep scanning now";
  const body =
    "You asked us to tell you when you could get more scans on SecScan. You can now.<br><br>" +
    `<strong>SecScan Unlimited</strong> — $19 a month: unlimited full scans (${fairUseText()}) and up to 3 sites ` +
    "watched around the clock. Cancel any time.<br>" +
    "Your 3 free scans every month are still there.";
  const ctaLabel = "See the plan";
  const ctaUrl = `${APP_ORIGIN}/settings#billing`;
  const footnote = "You're receiving this once, because you asked to be told. You won't get it again.";

  try {
    const res = await fetch(RESEND_API, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: resendBody({
        from: AUTH_FROM_EMAIL,
        to: [toEmail],
        subject: "You can keep scanning on SecScan.us now",
        html: buildAccountHtml(heading, body, ctaLabel, ctaUrl, footnote),
        text: buildAccountText(heading, body, ctaLabel, ctaUrl, footnote),
      }),
    });
    return res.ok ? "sent" : "failed";
  } catch {
    return "failed";
  }
}
