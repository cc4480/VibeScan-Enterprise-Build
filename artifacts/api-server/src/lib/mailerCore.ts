/** Shared Resend plumbing for every email: endpoints, HTML escaping, bulk-mail gating and the request body. */
import { FROM_EMAIL, REPLY_TO_EMAIL } from "./appOrigin";
import { htmlToPlainText } from "./htmlToText";
import { isSuppressed } from "./emailSuppression";
import { notificationPrefs, shouldNotify, type AlertKind } from "./notificationPrefs";

/**
 * Where mail is sent. Resend's API unless RESEND_BASE_URL says otherwise: an operator routing through a
 * compatible relay, or a test that needs to receive the messages the real code builds, sets it.
 */
const RESEND_BASE = (process.env["RESEND_BASE_URL"] ?? "https://api.resend.com").replace(/\/+$/, "");
export const RESEND_API = `${RESEND_BASE}/emails`;

/**
 * Escape text that came from a monitored site before it goes into email HTML.
 *
 * Drift details quote real header names and hostnames read off somebody else's
 * server. None of them should contain markup, which is exactly why an
 * unescaped one would be worth an attacker's time.
 */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export const RESEND_AUDIENCES_API = `${RESEND_BASE}/audiences`;

/**
 * Whether BULK mail may go to this address at all.
 *
 * Two independent reasons it may not: the person asked us to stop (the opt-out
 * in alertEmailsAllowed), or the provider told us to stop (a hard bounce or a
 * spam complaint — see lib/emailSuppression.ts). Both are checked in one place
 * so a new alert type cannot ship honouring one and ignoring the other.
 *
 * Account mail does NOT come through here: a sign-in code or a password reset
 * still goes to someone who complained about a newsletter, because suppressing
 * those would lock them out of their own account.
 */
export async function bulkMailAllowed(
  userId: string,
  toEmail: string,
  label: string,
  alert: { kind: AlertKind; severity?: string | null },
): Promise<boolean> {
  if (await isSuppressed(toEmail, "bulk")) {
    console.warn(`[mailer] Skipping ${label} — address is suppressed`);
    return false;
  }

  // Per-kind and severity preferences, on top of the master opt-out. Both are
  // resolved here rather than at each sender, so a new alert type cannot ship
  // honouring the suppression list and ignoring what the user asked for.
  const prefs = await notificationPrefs(userId);
  if (!shouldNotify(prefs, { kind: alert.kind, severity: alert.severity, channel: "email" })) {
    console.warn(`[mailer] Skipping ${label} — user's notification preferences`);
    return false;
  }

  return true;
}

/**
 * Build the Resend payload. Every outbound message goes through here, so `from`
 * and `reply_to` are applied uniformly — they were previously spelled out at
 * each call site, which is how a reply-to header goes missing on one email and
 * nobody notices until a customer's reply disappears.
 *
 * It ALWAYS attaches a plain-text alternative.
 *
 * Every message this service sent used to be HTML-only. Mail with no text part
 * scores worse with spam filters before a human sees it, and renders as nothing
 * in text-only clients. Rather than adding `text:` to a dozen call sites and
 * trusting the next one to remember, the text part is derived here from the
 * HTML whenever a caller has not supplied a better one — so it cannot go
 * missing again, including from a sender added later.
 *
 * A hand-written text body still wins where the wording matters, and the
 * senders that most need it pass one explicitly. This is the floor, not the
 * ceiling.
 */
export function resendBody(fields: Record<string, unknown>): string {
  const html = typeof fields["html"] === "string" ? (fields["html"] as string) : undefined;
  const supplied = typeof fields["text"] === "string" ? (fields["text"] as string).trim() : "";
  const text = supplied || (html ? htmlToPlainText(html) : "");

  return JSON.stringify({
    from: FROM_EMAIL,
    ...(REPLY_TO_EMAIL ? { reply_to: REPLY_TO_EMAIL } : {}),
    ...fields,
    ...(text ? { text } : {}),
  });
}
