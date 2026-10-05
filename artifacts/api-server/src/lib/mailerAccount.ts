/** Account emails: verification, sign-in code, password reset, purchase receipt. */
import { AUTH_FROM_EMAIL, APP_ORIGIN } from "./appOrigin";
import { htmlToPlainText } from "./htmlToText";
import { isSuppressed, healBounceSuppression } from "./emailSuppression";
import { RESEND_API, resendBody } from "./mailerCore";

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
      <h1 style="margin:0 0 12px;font-size:20px;line-height:1.3;">${heading}</h1>
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

/**
 * The two-factor sign-in code.
 *
 * THIS ONE THROWS, unlike every other sender in this module. Everywhere else a
 * failed send degrades to a warning, which is right for a receipt or an alert:
 * the user's request succeeded and the mail is a nicety. Here the mail IS the
 * sign-in. Swallowing the failure would tell the caller a code is on its way,
 * leave them at a code prompt forever, and lock them out of their own account
 * with nothing in the log to connect the two. The login route catches this and
 * says the code could not be sent.
 *
 * A missing RESEND_API_KEY throws for the same reason — an instance with no
 * mail provider cannot do two-factor sign-in, and must say so rather than
 * pretend.
 *
 * The code is rendered as text, never as a link: a clickable code would be
 * followed automatically by the mail scanners and prefetchers that made link
 * sign-in unreliable in the first place.
 */
export async function sendLoginCode(toEmail: string, code: string, ttlMinutes: number): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    throw new Error("RESEND_API_KEY is not set — two-factor sign-in codes cannot be sent");
  }

  // Reaching this point already means a correct password was just typed — the
  // strongest proof of legitimate access this app has short of the code itself
  // — so a stale hard bounce is given one more try before the check below can
  // block it. See healBounceSuppression.
  await healBounceSuppression(toEmail);

  // A hard bounce means this mailbox does not exist, so the code has nowhere to
  // go. THROWS rather than skipping, like the missing-key case above and for
  // the same reason: silently returning would tell the caller a code is on its
  // way and strand the user at a prompt they can never satisfy. A complaint
  // ("bulk" scope) does NOT block this — it is mail they just asked for.
  if (await isSuppressed(toEmail, "account")) {
    throw new Error("That address is on the suppression list after a permanent delivery failure");
  }
  const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
  const html = `<!DOCTYPE html>
<html><body style="margin:0;padding:24px;background:#f4f7f5;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#121a17;">
  <table role="presentation" width="100%" style="max-width:520px;margin:0 auto;background:#ffffff;border:1px solid #dbe4df;border-radius:8px;">
    <tr><td style="padding:28px;">
      <h1 style="margin:0 0 12px;font-size:20px;line-height:1.3;">Your sign-in code</h1>
      <p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#3c4b45;">Enter this code to finish signing in to SecScan.</p>
      <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:32px;font-weight:700;letter-spacing:6px;background:#f4f7f5;border:1px solid #dbe4df;border-radius:8px;padding:16px 24px;text-align:center;color:#121a17;">${spaced}</div>
      <p style="margin:20px 0 0;font-size:13px;line-height:1.6;color:#64766e;">It expires in ${ttlMinutes} minutes and can be used once. Spaces don't matter.</p>
      <p style="margin:16px 0 0;font-size:13px;line-height:1.6;color:#64766e;">If you didn't just try to sign in, someone may know your password — change it. They cannot get in without this code.</p>
    </td></tr>
  </table>
</body></html>`;

  const res = await fetch(RESEND_API, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    // The code is in the subject too: most clients preview enough of it to read
    // without opening the mail, which is the fastest way back to the waiting tab.
    body: resendBody({
      from: AUTH_FROM_EMAIL,
      to: [toEmail],
      subject: `${spaced} is your SecScan.us sign-in code`,
      html,
      // Written out rather than derived. This is the message a user reads when
      // they cannot get into their account, sometimes on a phone with images
      // off, and the derived version puts the code in a wall of styling.
      text:
        `Your SecScan sign-in code is ${spaced}\n\n` +
        `Enter it to finish signing in. It expires in ${ttlMinutes} minutes and can be used once. ` +
        `Spaces don't matter.\n\n` +
        `If you didn't just try to sign in, someone may know your password — change it. ` +
        `They cannot get in without this code.`,
    }),
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    throw new Error(`Resend API ${res.status}: ${errText}`);
  }
  console.log("[mailer] sign-in code sent", { to: toEmail });
}

/**
 * What an address that ALREADY has an account is sent when someone signs up with
 * it, in place of the sign-up code.
 *
 * POST /account/register answers a new address and an existing one with the
 * same reply, so the caller cannot use it to learn who has an account. The
 * people who CAN be told are the owners of the mailbox, and this is how: the
 * email says someone tried, that nothing changed, and how to get in.
 *
 * THIS ONE THROWS, for the same reason sendLoginCode does and with a second
 * one on top. The route must fail identically whether it was sending a code or
 * this notice: if a suppressed or unreachable address made a new sign-up answer
 * 502 but an existing account answer 202, that difference would be the oracle
 * back again. So it has the same guards in the same order — missing key, bounce
 * heal, suppression, then the request — and the same failure modes.
 *
 * It carries no code and no token. The only things in it are two links to
 * pages anyone can already open.
 */
export async function sendSignupExistingAccountEmail(toEmail: string): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    throw new Error("RESEND_API_KEY is not set — the sign-up notice cannot be sent");
  }

  // As in sendLoginCode: a sign-up for this address is a request that mail
  // reach it now, so a stale hard bounce is given one more try.
  await healBounceSuppression(toEmail);
  if (await isSuppressed(toEmail, "account")) {
    throw new Error("That address is on the suppression list after a permanent delivery failure");
  }

  const message: AccountMessage = {
    heading: "You already have an account",
    body:
      "Someone just tried to create a SecScan.us account with this email address. " +
      "There is already an account here, so nothing was created and nothing about your account was changed.<br><br>" +
      "If that was you, sign in instead. You will use your password and the code we email you, " +
      "or Google if that is how you signed up. " +
      `If you have forgotten your password, you can <a href="${APP_ORIGIN}/forgot-password">reset it</a>.`,
    ctaLabel: "Sign in",
    ctaUrl: `${APP_ORIGIN}/sign-in`,
    footnote:
      "If it wasn't you, you can ignore this email. Knowing your address is not enough to get into your account.",
  };

  const res = await fetch(RESEND_API, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    body: resendBody({
      from: AUTH_FROM_EMAIL,
      to: [toEmail],
      subject: "You already have a SecScan.us account",
      html: buildAccountHtml(message.heading, message.body, message.ctaLabel, message.ctaUrl, message.footnote),
      text: buildAccountText(message.heading, message.body, message.ctaLabel, message.ctaUrl, message.footnote),
    }),
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    throw new Error(`Resend API ${res.status}: ${errText}`);
  }
  console.log("[mailer] sign-up notice sent", { to: toEmail });
}

export async function sendPasswordReset(toEmail: string, resetUrl: string): Promise<void> {
  // Asking to reset a password is itself a signal someone can receive mail
  // here right now, so a stale hard bounce gets one more try. This is the ONLY
  // account-mail sender given that treatment on an anonymous request rather
  // than a proven password — deliberately so: the alternative is a bounce
  // permanently and silently stranding the real account owner, with the
  // /account/password/forgot route unable to say so without turning itself
  // into an account-existence oracle. See healBounceSuppression.
  await healBounceSuppression(toEmail);
  await sendAccountMessage(
    toEmail,
    "Reset your SecScan.us password",
    {
      heading: "Reset your password",
      body: "Use the link below to choose a new password. Signing in again will end any other sessions on your account.",
      ctaLabel: "Choose a new password",
      ctaUrl: resetUrl,
      footnote: "This link expires in 1 hour and can only be used once. If you didn't ask to reset your password, you can ignore this email — your current password still works.",
    },
    "password reset",
  );
}
