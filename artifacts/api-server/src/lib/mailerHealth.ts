/** Monitor alerts about certificate expiry and availability. */
import { APP_ORIGIN } from "./appOrigin";
import { unsubscribeHeaders } from "./emailPrefs";
import { bulkMailAllowed, escapeHtml, RESEND_API, resendBody } from "./mailerCore";

// ── Cert expiry email ──────────────────────────────────────────────────────────

export interface SendCertExpiryOptions {
  toEmail: string;
  /** Signs the unsubscribe link and identifies whose preference to honour. */
  userId: string;
  targetUrl: string;
  daysRemaining: number;
  expiryDate: Date;
  dashboardUrl: string;
}

export async function sendCertExpiryEmail(opts: SendCertExpiryOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

  if (!(await bulkMailAllowed(opts.userId, opts.toEmail, "cert expiry email", { kind: "cert_expiry" }))) {

    console.log("[mailer] Skipping cert expiry email", { to: opts.toEmail });

    return;

  }

  const { targetUrl, daysRemaining, expiryDate, dashboardUrl } = opts;
  const urgency = daysRemaining <= 7 ? "🚨 URGENT" : daysRemaining <= 14 ? "⚠️ Warning" : "📋 Notice";
  const expiryStr = expiryDate.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0f1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#f8fafc;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1117;min-height:100vh;">
    <tr><td align="center" style="padding:40px 16px;">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
        <tr><td style="padding-bottom:32px;text-align:center;">
          <span style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-1px;">Sec<span style="color:#6366f1;">Scan</span></span>
        </td></tr>
        <tr><td style="background:#1a1d27;border-radius:16px;border:1px solid rgba(255,255,255,0.08);padding:40px;text-align:center;">
          <div style="display:inline-block;font-size:48px;margin-bottom:16px;">🔒</div>
          <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;">TLS Certificate Expiring Soon</h2>
          <p style="margin:0 0 8px;font-size:18px;font-weight:700;color:#f8fafc;">${escapeHtml(targetUrl)}</p>
          <p style="margin:0 0 24px;color:#94a3b8;font-size:14px;">Certificate expires on <strong style="color:#facc15;">${expiryStr}</strong> — <strong style="color:#f8fafc;">${daysRemaining} day${daysRemaining !== 1 ? "s" : ""} remaining</strong>.</p>
          <p style="margin:0 0 32px;color:#94a3b8;font-size:13px;">Renew your TLS certificate immediately to avoid downtime and security warnings in browsers. Let's Encrypt certificates can be renewed with: <code style="background:#0f1117;padding:2px 6px;border-radius:4px;">certbot renew</code></p>
          <a href="${dashboardUrl}" style="display:inline-block;background:#6366f1;color:#fff;font-weight:700;font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;">View Monitor Dashboard →</a>
        </td></tr>
        <tr><td style="padding-top:24px;text-align:center;font-size:12px;color:#64748b;">
          <p style="margin:0;">© 2026 SecScan · <a href="${dashboardUrl}" style="color:#64748b;">Manage subscriptions</a></p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  try {
    const res = await fetch(RESEND_API, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: resendBody({
        headers: unsubscribeHeaders(APP_ORIGIN, opts.userId),
        to: [opts.toEmail],
        subject: `${urgency}: TLS certificate for ${targetUrl} expires in ${daysRemaining} days`,
        html,
      }),
    });
    if (!res.ok) throw new Error(`Resend API ${res.status}`);
    console.log("[mailer] Cert expiry email sent", { to: opts.toEmail, daysRemaining });
  } catch (err) {
    console.error("[mailer] Failed to send cert expiry email:", err);
  }
}

// ── Pulse-check alerts ────────────────────────────────────────────────────────

export interface SendAvailabilityOptions {
  toEmail: string;
  userId: string;
  targetUrl: string;
  /** "down" once an outage is confirmed, "recovered" when it ends. */
  event: "down" | "recovered";
  failureReason: string | null;
  /** How many consecutive hourly checks failed, for the down mail. */
  consecutiveFailures: number;
  /** When the site was last seen answering. Null if it never has been. */
  lastSeenUpAt: Date | null;
  dashboardUrl: string;
}

/**
 * Site went down, or came back.
 *
 * Deliberately plain. This mail exists to be read on a phone at an awkward
 * hour, so it leads with the domain and the reason and nothing else.
 */
export async function sendAvailabilityEmail(opts: SendAvailabilityOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

  if (!(await bulkMailAllowed(opts.userId, opts.toEmail, "availability email", { kind: "availability" }))) {
    console.log("[mailer] Skipping availability email", { to: opts.toEmail });
    return;
  }

  const { targetUrl, event, failureReason, consecutiveFailures, lastSeenUpAt, dashboardUrl } = opts;
  const down = event === "down";

  const heading = down ? "Site Unreachable" : "Site Back Online";
  const icon = down ? "🛑" : "✅";
  const accent = down ? "#ef4444" : "#22c55e";
  const detail = down
    ? `${failureReason ?? "No response"} — failed ${consecutiveFailures} consecutive hourly check${consecutiveFailures !== 1 ? "s" : ""}.`
    : "The site is answering again. Monitoring continues as normal.";
  const lastSeen = lastSeenUpAt
    ? `Last seen up ${lastSeenUpAt.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZoneName: "short" })}.`
    : "";

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0f1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#f8fafc;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1117;">
    <tr><td align="center" style="padding:40px 16px;">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
        <tr><td style="padding-bottom:32px;text-align:center;">
          <span style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-1px;">Sec<span style="color:#6366f1;">Scan</span></span>
        </td></tr>
        <tr><td style="background:#1a1d27;border-radius:16px;border:1px solid rgba(255,255,255,0.08);padding:40px;text-align:center;">
          <div style="display:inline-block;font-size:48px;margin-bottom:16px;">${icon}</div>
          <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;">${heading}</h2>
          <p style="margin:0 0 8px;font-size:18px;font-weight:700;color:${accent};">${escapeHtml(targetUrl)}</p>
          <p style="margin:0 0 8px;color:#94a3b8;font-size:14px;">${escapeHtml(detail)}</p>
          ${lastSeen ? `<p style="margin:0 0 24px;color:#64748b;font-size:13px;">${lastSeen}</p>` : ""}
          <p style="margin:0 0 32px;color:#64748b;font-size:12px;">SecScan checks every monitored URL once an hour. This is an availability check, not a security scan — your scan cadence is unchanged.</p>
          <a href="${dashboardUrl}" style="display:inline-block;background:#6366f1;color:#fff;font-weight:700;font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;">Open Monitoring →</a>
        </td></tr>
        <tr><td style="padding-top:24px;text-align:center;font-size:12px;color:#64748b;">
          <p style="margin:0;">© 2026 SecScan · <a href="${dashboardUrl}" style="color:#64748b;">Manage subscriptions</a></p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  try {
    const res = await fetch(RESEND_API, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: resendBody({
        headers: unsubscribeHeaders(APP_ORIGIN, opts.userId),
        to: [opts.toEmail],
        subject: down
          ? `🛑 ${targetUrl} is not responding`
          : `✅ ${targetUrl} is back online`,
        html,
      }),
    });
    if (!res.ok) throw new Error(`Resend API ${res.status}`);
    console.log("[mailer] Availability email sent", { to: opts.toEmail, event });
  } catch (err) {
    console.error("[mailer] Failed to send availability email:", err);
  }
}
