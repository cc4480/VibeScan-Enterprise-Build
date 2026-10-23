/** Monitor alerts about configuration drift and queued scans. */
import { APP_ORIGIN } from "./appOrigin";
import { unsubscribeHeaders } from "./emailPrefs";
import { describeDriftKind } from "./webhook";
import { bulkMailAllowed, escapeHtml, RESEND_API, resendBody } from "./mailerCore";

export interface SendDriftOptions {
  toEmail: string;
  userId: string;
  targetUrl: string;
  changes: Array<{ kind: string; detail: string; severity: string }>;
  /** Worst severity in the batch — the floor is applied to this, not the first. */
  severity: string;
  dashboardUrl: string;
}

/**
 * Something about the site's security configuration changed between scans.
 *
 * This is the alert that justifies checking hourly at all: a header removed on
 * a Tuesday afternoon used to go unnoticed until the next scheduled scan, which
 * on an A-grade site is up to fourteen days later.
 */
export async function sendDriftEmail(opts: SendDriftOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

  if (!(await bulkMailAllowed(opts.userId, opts.toEmail, "drift email", { kind: "drift", severity: opts.severity }))) {
    console.log("[mailer] Skipping drift email", { to: opts.toEmail });
    return;
  }

  const { targetUrl, changes, dashboardUrl } = opts;

  const rows = changes
    .map(
      (c) => `<tr>
        <td style="padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.06);color:#f8fafc;font-size:14px;font-weight:600;">${describeDriftKind(c.kind)}</td>
        <td style="padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.06);color:#94a3b8;font-size:13px;text-align:right;">${escapeHtml(c.detail)}</td>
      </tr>`,
    )
    .join("");

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
        <tr><td style="background:#1a1d27;border-radius:16px;border:1px solid rgba(255,255,255,0.08);padding:40px;">
          <div style="text-align:center;font-size:48px;margin-bottom:16px;">🔍</div>
          <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;text-align:center;">Security Configuration Changed</h2>
          <p style="margin:0 0 24px;font-size:16px;font-weight:700;color:#facc15;text-align:center;">${targetUrl}</p>
          <p style="margin:0 0 20px;color:#94a3b8;font-size:14px;">The hourly check found ${changes.length} change${changes.length !== 1 ? "s" : ""} that weaken${changes.length === 1 ? "s" : ""} this site's security posture since the last check:</p>
          <table width="100%" cellpadding="0" cellspacing="0">${rows}</table>
          <p style="margin:24px 0 32px;color:#64748b;font-size:12px;">Only changes that reduce protection are reported — a header being added is not an alert. If this was a deliberate deployment change, no action is needed.</p>
          <div style="text-align:center;">
            <a href="${dashboardUrl}" style="display:inline-block;background:#6366f1;color:#fff;font-weight:700;font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;">Open Monitoring →</a>
          </div>
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
        subject: `🔍 Security configuration changed on ${targetUrl}`,
        html,
      }),
    });
    if (!res.ok) throw new Error(`Resend API ${res.status}`);
    console.log("[mailer] Drift email sent", { to: opts.toEmail, changes: changes.length });
  } catch (err) {
    console.error("[mailer] Failed to send drift email:", err);
  }
}

export interface SendMonitorScanQueuedOptions {
  toEmail: string;
  /** Signs the unsubscribe link and identifies whose preference to honour. */
  userId: string;
  targetUrl: string;
  scanId: string;
  reason: "weekly" | "cve" | "adaptive";
  dashboardUrl: string;
}

export async function sendMonitorScanQueuedEmail(opts: SendMonitorScanQueuedOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

  if (!(await bulkMailAllowed(opts.userId, opts.toEmail, "monitor scan queued email", { kind: "scan_complete" }))) {

    console.log("[mailer] Skipping monitor scan queued email", { to: opts.toEmail });

    return;

  }

  const { targetUrl, reason, dashboardUrl } = opts;
  const label = reason === "weekly" ? "Weekly security rescan" : reason === "adaptive" ? "Scheduled security rescan" : "CVE-triggered rescan";

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
          <p style="margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:0.1em;color:#94a3b8;">${label}</p>
          <p style="margin:0 0 24px;font-size:18px;font-weight:600;color:#f8fafc;">${targetUrl}</p>
          <p style="margin:0 0 32px;font-size:14px;color:#94a3b8;">Your automated scan is running. You'll receive another email when the report is ready.</p>
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
        subject: `${label} started for ${targetUrl}`,
        html,
      }),
    });
    if (!res.ok) throw new Error(`Resend API ${res.status}`);
  } catch (err) {
    console.error("[mailer] Failed to send monitor scan queued email:", err);
  }
}
