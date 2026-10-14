/** Account emails: verification, sign-in code, password reset, purchase receipt. */
import { AUTH_FROM_EMAIL, APP_ORIGIN } from "./appOrigin";
import { htmlToPlainText } from "./htmlToText";
import { isSuppressed } from "./emailSuppression";
import { escapeHtml, RESEND_API, resendBody } from "./mailerCore";

// ── Account emails ────────────────────────────────────────────────────────────

/**
 * Plain, single-purpose account emails. Deliberately sparse next to the report
 * templates above: a verification or reset message competing for attention with
 * marketing chrome is how people learn to ignore them.
 */
export function buildAccountHtml(heading: string, body: string, ctaLabel: string, ctaUrl: string, footnote: string): string {
  return `<!DOCTYPE html>
<html><body style="margin:0;padding:24px;background:#f4f7f5;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#121a17;">
  <table role="presentation" width="100%" style="max-width:520px;margin:0 auto;background:#ffffff;border:1px solid #dbe4df;border-radius:8px;">
    <tr><td style="padding:28px;">
      <h1 style="margin:0 0 12px;font-size:20px;line-height:1.3;">${escapeHtml(heading)}</h1>
      <p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#3c4b45;">${body}</p>
      <a href="${ctaUrl}" style="display:inline-block;padding:11px 20px;background:#0e9463;color:#ffffff;text-decoration:none;border-radius:6px;font-size:14px;font-weight:600;">${ctaLabel}</a>
      <p style="margin:20px 0 0;font-size:13px;line-height:1.6;color:#64766e;">${footnote}</p>
      <p style="margin:16px 0 0;font-size:12px;line-height:1.5;color:#64766e;word-break:break-all;">If the button doesn't work, paste this into your browser:<br>${ctaUrl}</p>
    </td></tr>
  </table>
</body></html>`;
}

/**
 * The plain-text twin of buildAccountHtml, from the same inputs.
 *
 * Written rather than derived: these four messages (verification, reset,
 * receipt, welcome) are the ones a user reads when something has gone wrong or
 * money has moved, and the derived version buries the link in punctuation.
 */
export function buildAccountText(heading: string, body: string, ctaLabel: string, ctaUrl: string, footnote: string): string {
  // `body` carries inline markup (the receipt bolds the amount), so it goes
  // through the same stripper rather than being pasted in raw — a text part
  // containing "<strong>$29.00</strong>" is worse than no text part.
  return [heading, "", htmlToPlainText(body), "", `${ctaLabel}: ${ctaUrl}`, "", footnote].join("\n");
}

export interface AccountMessage {
  heading: string;
  body: string;
  ctaLabel: string;
  ctaUrl: string;
  footnote: string;
}

/**
 * Send one account email, rendering BOTH parts from the same content.
 *
 * Callers pass the message once. Handing the same five strings to an HTML
 * builder and a text builder separately is how the two versions drift until
 * they say different things — which is worse than having only one.
 */
export async function sendAccountMessage(to: string, subject: string, m: AccountMessage, label: string): Promise<void> {
  await sendAccountEmail(
    to,
    subject,
    buildAccountHtml(m.heading, m.body, m.ctaLabel, m.ctaUrl, m.footnote),
    label,
    buildAccountText(m.heading, m.body, m.ctaLabel, m.ctaUrl, m.footnote),
  );
}

export async function sendAccountEmail(to: string, subject: string, html: string, label: string, text?: string): Promise<void> {
  // "account" kind: still sent to someone who complained, because these are
  // messages their own action just asked for — a reset link, a receipt.
  // Suppressing them over a newsletter complaint would lock people out of
  // their accounts. A hard-bounced address stops everything, including these.
  if (await isSuppressed(to, "account")) {
    console.warn(`[mailer] Skipping ${label} — address is suppressed`);
    return;
  }
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    // Matches the rest of this module: a missing key degrades to a warning
    // rather than failing the request that triggered it.
    console.warn(`[mailer] RESEND_API_KEY is not set — skipping ${label}`);
    return;
  }

  try {
    const res = await fetch(RESEND_API, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      // Account mail, so it leaves from the account sender — see AUTH_FROM_EMAIL.
      body: resendBody({ from: AUTH_FROM_EMAIL, to: [to], subject, html, ...(text ? { text } : {}) }),
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`Resend API ${res.status}: ${errText}`);
    }
    console.log(`[mailer] ${label} sent`, { to });
  } catch (err) {
    console.error(`[mailer] Failed to send ${label}:`, err);
  }
}

/**
 * Receipt for a completed Stripe purchase. Stripe can email its own receipt,
 * but only if that is switched on in the Stripe dashboard, and it says nothing
 * about what the money actually bought here — a single scan versus a credit
 * pack, and how many credits landed. Sent from our side so the customer always
 * has one, and always has one that names the product.
 *
 * `amountCents` is the amount Stripe charged, in the smallest currency unit.
 */
export async function sendPurchaseReceiptEmail(opts: {
  toEmail: string;
  productName: string;
  amountCents: number;
  creditsAdded?: number;
}): Promise<void> {
  const amount = `$${(opts.amountCents / 100).toFixed(2)}`;
  const detail = opts.creditsAdded
    ? `${opts.creditsAdded} scan credit${opts.creditsAdded === 1 ? "" : "s"} ${opts.creditsAdded === 1 ? "has" : "have"} been added to your account and never expire.`
    : "Your scan has been queued and you'll get a separate email as soon as the report is ready.";

  await sendAccountMessage(
    opts.toEmail,
    `Your SecScan receipt — ${opts.productName}`,
    {
      heading: "Thanks for your purchase",
      body: `You paid <strong>${amount}</strong> for <strong>${opts.productName}</strong>. ${detail}`,
      ctaLabel: "Go to your dashboard",
      ctaUrl: `${APP_ORIGIN}/dashboard`,
      footnote: "This is a receipt for your records. Reply to this email if anything looks wrong.",
    },
    "purchase receipt",
  );
}

export async function sendEmailVerification(toEmail: string, verifyUrl: string): Promise<void> {
  await sendAccountMessage(
    toEmail,
    "Confirm your email for SecScan",
    {
      heading: "Confirm your email",
      body: "Confirming your address lets us send you scan results and security alerts, and lets you get back into your account if you forget your password.",
      ctaLabel: "Confirm email",
      ctaUrl: verifyUrl,
      footnote: "This link expires in 24 hours. If you didn't create a SecScan account, you can ignore this email.",
    },
    "email verification",
  );
}
