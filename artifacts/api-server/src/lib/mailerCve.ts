/** Monitor alerts about new CVEs and regressions. */
import { APP_ORIGIN } from "./appOrigin";
import { unsubscribeHeaders } from "./emailPrefs";
import { highestSeverity } from "./notificationPrefs";
import { bulkMailAllowed, escapeHtml, RESEND_API, resendBody } from "./mailerCore";

// ── Monitor emails ─────────────────────────────────────────────────────────────

export interface CveMatch {
  cveId: string;
  summary: string;
  severity: string;
  affectedTech: string;
}

export interface SendMonitorCveAlertOptions {
  toEmail: string;
  /** Signs the unsubscribe link and identifies whose preference to honour. */
  userId: string;
  targetUrl: string;
  cveMatches: CveMatch[];
  scanId: string;
  dashboardUrl: string;
}

export const SEVERITY_COLOR: Record<string, string> = {
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

  if (!(await bulkMailAllowed(opts.userId, opts.toEmail, "CVE alert email", { kind: "cve", severity: highestSeverity(opts.cveMatches) }))) {

    console.log("[mailer] Skipping CVE alert email", { to: opts.toEmail });

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
          <span style="font-family:monospace;font-size:13px;color:#a5b4fc;">${escapeHtml(m.cveId)}</span>
          <span style="margin-left:8px;font-size:11px;background:${SEVERITY_COLOR[m.severity] ?? "#94a3b8"}22;color:${SEVERITY_COLOR[m.severity] ?? "#94a3b8"};padding:2px 8px;border-radius:12px;font-weight:700;">${m.severity}</span>
          <br/>
          <span style="font-size:12px;color:#64748b;">${escapeHtml(m.affectedTech)}</span>
          <br/>
          <span style="font-size:12px;color:#94a3b8;">${escapeHtml(m.summary)}</span>
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
          <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;">New vulnerabilities in software your site runs</h2>
          <p style="margin:0 0 24px;color:#94a3b8;font-size:14px;">
            <strong style="color:#f8fafc;">${cveMatches.length} CVE${cveMatches.length > 1 ? "s" : ""}</strong>, newly published or newly analysed by the NVD, list software detected on
            <strong style="color:#f8fafc;">${escapeHtml(targetUrl)}</strong> as vulnerable.
            Each one below says whether the version we detected is in the affected range, or whether no version could be detected.
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
          <p style="margin:0;">You received this because you have a SecScan continuous monitor active for ${escapeHtml(targetUrl)}.</p>
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
        headers: unsubscribeHeaders(APP_ORIGIN, opts.userId),
        to: [opts.toEmail],
        subject: `⚠ CVE Alert: ${topMatch?.cveId ?? "New vulnerability"}${extra} in software detected on ${targetUrl}`,
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

export interface SendRegressionAlertOptions {
  toEmail: string;
  /** Signs the unsubscribe link and identifies whose preference to honour. */
  userId: string;
  targetUrl: string;
  regressions: RegressionItem[];
  scanId: string;
  dashboardUrl: string;
}

export async function sendRegressionAlertEmail(opts: SendRegressionAlertOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

  if (!(await bulkMailAllowed(opts.userId, opts.toEmail, "regression alert email", { kind: "regression", severity: highestSeverity(opts.regressions) }))) {

    console.log("[mailer] Skipping regression alert email", { to: opts.toEmail });

    return;

  }

  const { targetUrl, regressions, dashboardUrl } = opts;

  const rows = regressions.slice(0, 8).map((r) => {
    const color = SEVERITY_COLOR[r.severity.toUpperCase()] ?? "#94a3b8";
    return `
      <tr>
        <td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.06);">
          <span style="font-size:11px;background:${color}22;color:${color};padding:2px 8px;border-radius:12px;font-weight:700;margin-right:8px;">${r.severity}</span>
          <span style="font-size:14px;color:#f8fafc;">${escapeHtml(r.checkTitle)}</span>
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
            <strong style="color:#f8fafc;">${escapeHtml(targetUrl)}</strong>.
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
        headers: unsubscribeHeaders(APP_ORIGIN, opts.userId),
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
