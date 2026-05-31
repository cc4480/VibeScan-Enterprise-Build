/**
 * Email notifications via Resend API.
 * Used to send report-ready emails after deep/pack scan completion,
 * and monitor subscription alerts (CVE matches, weekly scan queued).
 * Requires RESEND_API_KEY environment variable.
 */

const RESEND_API = "https://api.resend.com/emails";
const FROM_EMAIL = "Seclayer <reports@seclayer.app>";

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
          <span style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-1px;">Sec<span style="color:#6366f1;">layer</span></span>
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
          <p style="margin:0;">You received this because you ran a Seclayer deep scan.</p>
          <p style="margin:4px 0 0;">© 2026 Seclayer</p>
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
      body: JSON.stringify({
        from: FROM_EMAIL,
        to: [opts.toEmail],
        subject: `Your Seclayer report is ready — Grade ${opts.grade} for ${opts.targetUrl}`,
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
          <span style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-1px;">Sec<span style="color:#6366f1;">layer</span></span>
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
          <p style="margin:0;">You received this because you have a Seclayer continuous monitor active for ${targetUrl}.</p>
          <p style="margin:4px 0 0;">© 2026 Seclayer · <a href="${dashboardUrl}" style="color:#64748b;">Manage subscriptions</a></p>
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
      body: JSON.stringify({
        from: FROM_EMAIL,
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

interface SendMonitorScanQueuedOptions {
  toEmail: string;
  targetUrl: string;
  scanId: string;
  reason: "weekly" | "cve";
  dashboardUrl: string;
}

export async function sendMonitorScanQueuedEmail(opts: SendMonitorScanQueuedOptions): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

  const { targetUrl, reason, dashboardUrl } = opts;
  const label = reason === "weekly" ? "Weekly security rescan" : "CVE-triggered rescan";

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0f1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#f8fafc;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1117;min-height:100vh;">
    <tr><td align="center" style="padding:40px 16px;">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
        <tr><td style="padding-bottom:32px;text-align:center;">
          <span style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-1px;">Sec<span style="color:#6366f1;">layer</span></span>
        </td></tr>
        <tr><td style="background:#1a1d27;border-radius:16px;border:1px solid rgba(255,255,255,0.08);padding:40px;text-align:center;">
          <p style="margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:0.1em;color:#94a3b8;">${label}</p>
          <p style="margin:0 0 24px;font-size:18px;font-weight:600;color:#f8fafc;">${targetUrl}</p>
          <p style="margin:0 0 32px;font-size:14px;color:#94a3b8;">Your automated scan is running. You'll receive another email when the report is ready.</p>
          <a href="${dashboardUrl}" style="display:inline-block;background:#6366f1;color:#fff;font-weight:700;font-size:15px;padding:14px 32px;border-radius:10px;text-decoration:none;">View Monitor Dashboard →</a>
        </td></tr>
        <tr><td style="padding-top:24px;text-align:center;font-size:12px;color:#64748b;">
          <p style="margin:0;">© 2026 Seclayer · <a href="${dashboardUrl}" style="color:#64748b;">Manage subscriptions</a></p>
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
      body: JSON.stringify({
        from: FROM_EMAIL,
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
