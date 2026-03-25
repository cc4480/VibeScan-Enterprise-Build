/**
 * Email notifications via Resend API.
 * Used to send report-ready emails after deep/pack scan completion.
 * Requires RESEND_API_KEY environment variable.
 */

const RESEND_API = "https://api.resend.com/emails";
const FROM_EMAIL = "VibeScan <reports@vibescan.app>";

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
          <span style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-1px;">Vibe<span style="color:#6366f1;">Scan</span></span>
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
          <p style="margin:0;">You received this because you ran a VibeScan deep scan.</p>
          <p style="margin:4px 0 0;">© 2025 VibeScan</p>
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
        subject: `Your VibeScan report is ready — Grade ${opts.grade} for ${opts.targetUrl}`,
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
