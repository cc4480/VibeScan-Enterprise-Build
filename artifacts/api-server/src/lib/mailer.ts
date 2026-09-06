/**
 * Email notifications via Resend API.
 * Used to send report-ready emails after deep/pack scan completion,
 * and monitor subscription alerts (CVE matches, weekly scan queued).
 * Requires RESEND_API_KEY environment variable.
 */

import { FROM_EMAIL, REPLY_TO_EMAIL, APP_ORIGIN } from "./appOrigin";

const RESEND_API = "https://api.resend.com/emails";
const RESEND_AUDIENCES_API = "https://api.resend.com/audiences";

/**
 * Every outbound message goes through here so `from` and `reply_to` are
 * applied uniformly. They were previously spelled out at each call site,
 * which is how a reply-to header goes missing on one email and nobody
 * notices until a customer's reply disappears.
 */
function resendBody(fields: Record<string, unknown>): string {
  return JSON.stringify({
    from: FROM_EMAIL,
    ...(REPLY_TO_EMAIL ? { reply_to: REPLY_TO_EMAIL } : {}),
    ...fields,
  });
}

interface SendReportEmailOptions {
  toEmail: string;
  targetUrl: string;
  grade: string;
  riskScore: number;
  totalVulns: number;
  reportUrl: string;
  tier: string;
}

function buildHtml(opts: SendReportEmailOptions): string {
  const { targetUrl, grade, riskScore, totalVulns, reportUrl } = opts;

  const gradeColors: Record<string, string> = {
    A: "#34d399",
    B: "#a3e635",
    C: "#facc15",
    D: "#fb923c",
    F: "#f87171",
  };
  const gradeColor = gradeColors[grade] ?? "#94a3b8";

  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0f1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#f8fafc;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1117;min-height:100vh;">
    <tr><td align="center" style="padding:40px 16px;">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
        <!-- Header -->
        <tr><td style="padding-bottom:32px;text-align:center;">
          <span style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-1px;">Sec<span style="color:#6366f1;">Scan</span></span>
        </td></tr>

        <!-- Grade Card -->
        <tr><td style="background:#1a1d27;border-radius:16px;border:1px solid rgba(255,255,255,0.08);padding:40px;text-align:center;">
          <p style="margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:0.1em;color:#94a3b8;">Security Scan Complete</p>
          <p style="margin:0 0 24px;font-size:18px;font-weight:600;color:#f8fafc;">${targetUrl}</p>

          <div style="display:inline-block;background:#0f1117;border-radius:50%;width:120px;height:120px;line-height:120px;text-align:center;margin-bottom:24px;border:4px solid ${gradeColor};">
            <span style="font-size:60px;font-weight:900;color:${gradeColor};line-height:1;">${grade}</span>
          </div>

          <p style="margin:0 0 8px;font-size:14px;color:#94a3b8;">Risk Score: <strong style="color:#f8fafc;">${riskScore}/100</strong></p>
          <p style="margin:0 0 32px;font-size:14px;color:#94a3b8;">Vulnerabilities Found: <strong style="color:#f8fafc;">${totalVulns}</strong></p>

          <a href="${reportUrl}" style="display:inline-block;background:#6366f1;color:#fff;font-weight:700;font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;">View Full Report →</a>
        </td></tr>

        <!-- Footer -->
        <tr><td style="padding-top:24px;text-align:center;font-size:12px;color:#64748b;">
          <p style="margin:0;">You received this because you ran a SecScan deep scan.</p>
          <p style="margin:4px 0 0;">© 2026 SecScan</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

export async function sendReportReadyEmail(opts: SendReportEmailOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.warn("[mailer] RESEND_API_KEY is not set — skipping email notification");
    return;
  }

  try {
    const res = await fetch(RESEND_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: resendBody({
        to: [opts.toEmail],
        subject: `Your SecScan report is ready — Grade ${opts.grade} for ${opts.targetUrl}`,
        html: buildHtml(opts),
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`Resend API ${res.status}: ${errText}`);
    }

    const json = (await res.json()) as { id?: string };
    console.log("[mailer] Report-ready email sent", { emailId: json.id, to: opts.toEmail });
  } catch (err) {
    console.error("[mailer] Failed to send email:", err);
  }
}

// ── Monitor emails ─────────────────────────────────────────────────────────────

interface CveMatch {
  cveId: string;
  summary: string;
  severity: string;
  affectedTech: string;
}

interface SendMonitorCveAlertOptions {
  toEmail: string;
  targetUrl: string;
  cveMatches: CveMatch[];
  scanId: string;
  dashboardUrl: string;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#a3e635",
  UNKNOWN: "#94a3b8",
};

export async function sendMonitorCveAlertEmail(opts: SendMonitorCveAlertOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.warn("[mailer] RESEND_API_KEY is not set — skipping CVE alert email");
    return;
  }

  const { targetUrl, cveMatches, dashboardUrl } = opts;
  const topMatch = cveMatches[0];
  const extra = cveMatches.length > 1 ? ` (+${cveMatches.length - 1} more)` : "";

  const cveRows = cveMatches
    .slice(0, 5)
    .map(
      (m) => `
      <tr>
        <td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.06);">
          <span style="font-family:monospace;font-size:13px;color:#a5b4fc;">${m.cveId}</span>
          <span style="margin-left:8px;font-size:11px;background:${SEVERITY_COLOR[m.severity] ?? "#94a3b8"}22;color:${SEVERITY_COLOR[m.severity] ?? "#94a3b8"};padding:2px 8px;border-radius:12px;font-weight:700;">${m.severity}</span>
          <br/>
          <span style="font-size:12px;color:#64748b;">${m.affectedTech}</span>
          <br/>
          <span style="font-size:12px;color:#94a3b8;">${m.summary}</span>
        </td>
      </tr>
    `,
    )
    .join("");

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

        <tr><td style="background:#1a1d27;border-radius:16px;border:1px solid rgba(255,255,255,0.08);padding:40px;">
          <div style="display:inline-flex;align-items:center;gap:8px;background:#f8717122;padding:6px 14px;border-radius:20px;margin-bottom:24px;">
            <span style="font-size:13px;font-weight:700;color:#f87171;">⚠ CVE Alert</span>
          </div>
          <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;">New vulnerabilities affect your stack</h2>
          <p style="margin:0 0 24px;color:#94a3b8;font-size:14px;">
            <strong style="color:#f8fafc;">${cveMatches.length} new CVE${cveMatches.length > 1 ? "s" : ""}</strong> published today match technologies detected on
            <strong style="color:#f8fafc;">${targetUrl}</strong>.
            A rescan has been queued automatically.
          </p>

          <table width="100%" cellpadding="0" cellspacing="0">
            ${cveRows}
          </table>

          <div style="margin-top:32px;text-align:center;">
            <a href="${dashboardUrl}" style="display:inline-block;background:#6366f1;color:#fff;font-weight:700;font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;">View Monitor Dashboard →</a>
          </div>
        </td></tr>

        <tr><td style="padding-top:24px;text-align:center;font-size:12px;color:#64748b;">
          <p style="margin:0;">You received this because you have a SecScan continuous monitor active for ${targetUrl}.</p>
          <p style="margin:4px 0 0;">© 2026 SecScan · <a href="${dashboardUrl}" style="color:#64748b;">Manage subscriptions</a></p>
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
        to: [opts.toEmail],
        subject: `⚠ CVE Alert: ${topMatch?.cveId ?? "New vulnerability"}${extra} affects ${targetUrl}`,
        html,
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`Resend API ${res.status}: ${errText}`);
    }

    console.log("[mailer] CVE alert email sent", { to: opts.toEmail, matches: cveMatches.length });
  } catch (err) {
    console.error("[mailer] Failed to send CVE alert email:", err);
  }
}

// ── Regression alert email ─────────────────────────────────────────────────────

export interface RegressionItem {
  checkTitle: string;
  severity: string;
}

interface SendRegressionAlertOptions {
  toEmail: string;
  targetUrl: string;
  regressions: RegressionItem[];
  scanId: string;
  dashboardUrl: string;
}

export async function sendRegressionAlertEmail(opts: SendRegressionAlertOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

  const { targetUrl, regressions, dashboardUrl } = opts;

  const rows = regressions.slice(0, 8).map((r) => {
    const color = SEVERITY_COLOR[r.severity.toUpperCase()] ?? "#94a3b8";
    return `
      <tr>
        <td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.06);">
          <span style="font-size:11px;background:${color}22;color:${color};padding:2px 8px;border-radius:12px;font-weight:700;margin-right:8px;">${r.severity}</span>
          <span style="font-size:14px;color:#f8fafc;">${r.checkTitle}</span>
        </td>
      </tr>`;
  }).join("");

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
        <tr><td style="background:#1a1d27;border-radius:16px;border:1px solid rgba(255,255,255,0.08);padding:40px;">
          <div style="display:inline-flex;align-items:center;gap:8px;background:#fb923c22;padding:6px 14px;border-radius:20px;margin-bottom:24px;">
            <span style="font-size:13px;font-weight:700;color:#fb923c;">🔴 Security Regression</span>
          </div>
          <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;">Security checks are now failing</h2>
          <p style="margin:0 0 24px;color:#94a3b8;font-size:14px;">
            <strong style="color:#f8fafc;">${regressions.length} check${regressions.length > 1 ? "s" : ""}</strong> that previously passed are now failing on
            <strong style="color:#f8fafc;">${targetUrl}</strong>.
          </p>
          <table width="100%" cellpadding="0" cellspacing="0">${rows}</table>
          <div style="margin-top:32px;text-align:center;">
            <a href="${dashboardUrl}" style="display:inline-block;background:#6366f1;color:#fff;font-weight:700;font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;">View Monitor Dashboard →</a>
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
        to: [opts.toEmail],
        subject: `🔴 Regression alert: ${regressions.length} security check${regressions.length > 1 ? "s" : ""} failing on ${targetUrl}`,
        html,
      }),
    });
    if (!res.ok) throw new Error(`Resend API ${res.status}`);
    console.log("[mailer] Regression alert email sent", { to: opts.toEmail });
  } catch (err) {
    console.error("[mailer] Failed to send regression alert email:", err);
  }
}

// ── Cert expiry email ──────────────────────────────────────────────────────────

interface SendCertExpiryOptions {
  toEmail: string;
  targetUrl: string;
  daysRemaining: number;
  expiryDate: Date;
  dashboardUrl: string;
}

export async function sendCertExpiryEmail(opts: SendCertExpiryOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

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
          <p style="margin:0 0 8px;font-size:18px;font-weight:700;color:#f8fafc;">${targetUrl}</p>
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

interface SendMonitorScanQueuedOptions {
  toEmail: string;
  targetUrl: string;
  scanId: string;
  reason: "weekly" | "cve" | "adaptive";
  dashboardUrl: string;
}

export async function sendMonitorScanQueuedEmail(opts: SendMonitorScanQueuedOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

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

// ── Account emails ────────────────────────────────────────────────────────────

/**
 * Plain, single-purpose account emails. Deliberately sparse next to the report
 * templates above: a verification or reset message competing for attention with
 * marketing chrome is how people learn to ignore them.
 */
function buildAccountHtml(heading: string, body: string, ctaLabel: string, ctaUrl: string, footnote: string): string {
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

async function sendAccountEmail(to: string, subject: string, html: string, label: string): Promise<void> {
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
      body: resendBody({ to: [to], subject, html }),
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
    ? `${opts.creditsAdded} deep-scan credit${opts.creditsAdded === 1 ? "" : "s"} have been added to your account and never expire.`
    : "Your scan has been queued and you'll get a separate email as soon as the report is ready.";

  await sendAccountEmail(
    opts.toEmail,
    `Your SecScan receipt — ${opts.productName}`,
    buildAccountHtml(
      "Thanks for your purchase",
      `You paid <strong>${amount}</strong> for <strong>${opts.productName}</strong>. ${detail}`,
      "Go to your dashboard",
      `${APP_ORIGIN}/dashboard`,
      "This is a receipt for your records. Reply to this email if anything looks wrong.",
    ),
    "purchase receipt",
  );
}

export async function sendEmailVerification(toEmail: string, verifyUrl: string): Promise<void> {
  await sendAccountEmail(
    toEmail,
    "Confirm your email for SecScan",
    buildAccountHtml(
      "Confirm your email",
      "Confirming your address lets us send you scan results and security alerts, and lets you get back into your account if you forget your password.",
      "Confirm email",
      verifyUrl,
      "This link expires in 24 hours. If you didn't create a SecScan account, you can ignore this email.",
    ),
    "email verification",
  );
}

export async function sendPasswordReset(toEmail: string, resetUrl: string): Promise<void> {
  await sendAccountEmail(
    toEmail,
    "Reset your SecScan password",
    buildAccountHtml(
      "Reset your password",
      "Use the link below to choose a new password. Signing in again will end any other sessions on your account.",
      "Choose a new password",
      resetUrl,
      "This link expires in 1 hour and can only be used once. If you didn't ask to reset your password, you can ignore this email — your current password still works.",
    ),
    "password reset",
  );
}

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
  await sendAccountEmail(
    toEmail,
    "Welcome to SecScan",
    buildAccountHtml(
      firstName ? `Welcome, ${firstName}` : "Welcome to SecScan",
      "SecScan runs real vulnerability checks, not a checklist: SQL injection, exposed secrets, misconfigured databases, and more. We'll email you when there's something worth knowing: new features, security research, and the occasional product update. Account and security emails (password resets, scan reports) always go out regardless.",
      "Run your first scan",
      `${APP_ORIGIN}/dashboard`,
      "You can unsubscribe from product updates at any time via the link included in those emails.",
    ),
    "welcome email",
  );
}
