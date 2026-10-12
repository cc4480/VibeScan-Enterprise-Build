/** The report-ready email. */
import { APP_ORIGIN } from "./appOrigin";
import { isSuppressed } from "./emailSuppression";
import { escapeHtml, RESEND_API, resendBody } from "./mailerCore";

export interface SendReportEmailOptions {
  toEmail: string;
  targetUrl: string;
  grade: string;
  riskScore: number;
  totalVulns: number;
  reportUrl: string;
  tier: string;
  /** How many tests ran, were skipped or failed. Absent means "not recorded", and nothing is claimed. */
  coverage?: { ran: number; skipped: number; failed: number; total: number };
  /** Findings per severity. Absent on callers that do not have it; the row is then left out. */
  severity?: { critical: number; high: number; medium: number; low: number; info: number };
  /** The report's own summary sentence, so the email says what the report header says. */
  executiveSummary?: string;
  /** Pages the scan covered, for the "Scanned N pages" pill. */
  pagesScanned?: number;
  /** "2 new, 3 fixed since your last scan (20 Sep)" (lib/scanDiff.ts). Absent for a first scan or when nothing changed. */
  changesLine?: string;
}

export const GRADE_COLORS: Record<string, string> = {
  A: "#22c55e",
  B: "#84cc16",
  C: "#eab308",
  D: "#f97316",
  F: "#ef4444",
};

export const SEVERITY_STYLE: Array<{ key: keyof NonNullable<SendReportEmailOptions["severity"]>; label: string; color: string }> = [
  { key: "critical", label: "Critical", color: "#ef4444" },
  { key: "high", label: "High", color: "#f97316" },
  { key: "medium", label: "Medium", color: "#eab308" },
  { key: "low", label: "Low", color: "#60a5fa" },
  { key: "info", label: "Info", color: "#a1a1aa" },
];

/** One line that says what matters, so the email is useful even unopened. */
export function verdict(opts: SendReportEmailOptions): string {
  const sev = opts.severity;
  if (sev) {
    const urgent = sev.critical + sev.high;
    if (sev.critical > 0) return `${sev.critical} critical ${sev.critical === 1 ? "issue needs" : "issues need"} fixing now.`;
    if (urgent > 0) return `${urgent} high-severity ${urgent === 1 ? "issue needs" : "issues need"} attention.`;
  }
  if (opts.totalVulns === 0) return "No issues found by the tests that ran.";
  return "No critical or high-severity issues found.";
}

/**
 * The report-ready email, built to look like the report page it links to: the
 * app's nav mark, the grade ring with "RISK", the URL and "Scanned N pages"
 * pills, the "Security Report" title in the display face, the report's own
 * summary sentence and its severity dots — so the email reads as SecScan, not
 * as a generic notification. Colours are the app's tokens (index.css):
 * background #09090b, card #18181b, border #27272a, primary #22c55e, muted
 * #a1a1aa; Space Grotesk for display, Inter for text, with system fallbacks
 * for clients that ignore web fonts. Table layout and inline styles throughout,
 * because that is what mail clients render reliably.
 */
export function buildHtml(opts: SendReportEmailOptions): string {
  const { targetUrl, grade, riskScore, totalVulns, reportUrl, coverage, severity } = opts;
  const gradeColor = GRADE_COLORS[grade] ?? "#71717a";
  const href = escapeHtml(reportUrl);
  const origin = escapeHtml(APP_ORIGIN);
  const display = "'Space Grotesk','Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif";
  const body = "'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
  // The full URL as the report shows it. Gmail and Outlook auto-link anything
  // shaped like a domain, which invites a click to the scanned site instead of
  // the report; an invisible zero-width space after each dot prevents that.
  const shownUrl = escapeHtml(targetUrl).replace(/\./g, ".&#8203;").replace(/:\/\//, ":&#8203;//");
  const summaryText = opts.executiveSummary?.trim() || verdict(opts);

  const notRun = coverage ? coverage.skipped + coverage.failed : 0;
  const testsTile =
    coverage && coverage.total > 0
      ? `<td width="33%" style="padding:0 0 0 6px;">
            <div style="background:#18181b;border:1px solid #27272a;border-radius:16px;padding:18px 8px;text-align:center;">
              <div style="font-family:${display};font-size:26px;font-weight:700;color:#fafafa;line-height:1.1;">${coverage.ran}<span style="font-size:15px;color:#71717a;">/${coverage.total}</span></div>
              <div style="font-size:12px;color:#a1a1aa;margin-top:6px;">Tests run</div>
            </div>
          </td>`
      : "";
  const coverageNote =
    notRun > 0
      ? `<p style="margin:14px 0 0;font-size:12px;line-height:1.6;color:#71717a;text-align:center;">${notRun} ${notRun === 1 ? "test" : "tests"} did not run on this scan. A clean result says nothing about ${notRun === 1 ? "that area" : "those areas"}; the report lists ${notRun === 1 ? "it" : "them"} and why.</p>`
      : "";

  // The report header's severity dots: only the severities that occur.
  const dots = severity
    ? SEVERITY_STYLE.filter((sv) => severity[sv.key] > 0)
        .map(
          (sv) =>
            `<span style="display:inline-block;margin:0 8px;font-size:13px;color:#a1a1aa;white-space:nowrap;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${sv.color};margin-right:6px;vertical-align:middle;"></span><strong style="color:#fafafa;">${severity[sv.key]}</strong> ${sv.label}</span>`,
        )
        .join("")
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="supported-color-schemes" content="dark">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Space+Grotesk:wght@700&display=swap" rel="stylesheet">
<title>Your SecScan security report</title>
</head>
<body style="margin:0;padding:0;background:#09090b;font-family:${body};color:#fafafa;-webkit-text-size-adjust:100%;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">Grade ${escapeHtml(grade)} · ${escapeHtml(summaryText)}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#09090b;">
    <tr><td align="center" style="padding:28px 14px 36px;">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

        <!-- Nav: the app's mark and wordmark -->
        <tr><td style="padding:0 2px 22px;">
          <a href="${origin}" style="text-decoration:none;">
            <img src="${origin}/icon-192.png?v=2" width="34" height="34" alt="SecScan" style="display:inline-block;vertical-align:middle;border:0;border-radius:9px;">
            <span style="display:inline-block;vertical-align:middle;margin-left:10px;font-family:${display};font-size:19px;font-weight:700;color:#fafafa;letter-spacing:-0.2px;">SecScan</span>
          </a>
        </td></tr>

        <!-- Report header, as on the report page -->
        <tr><td style="background:#111113;background-image:linear-gradient(180deg,#141a16 0%,#111113 60%);border:1px solid #27272a;border-radius:24px;padding:34px 26px 30px;text-align:center;">

          <!-- Grade ring -->
          <table role="presentation" align="center" cellpadding="0" cellspacing="0" style="margin:0 auto;"><tr><td>
            <div style="width:136px;height:136px;border-radius:50%;border:7px solid ${gradeColor};box-shadow:0 0 36px ${gradeColor}33;background:#09090b;text-align:center;">
              <div style="font-family:${display};font-size:58px;font-weight:700;line-height:1;color:${gradeColor};padding-top:30px;">${escapeHtml(grade)}</div>
              <div style="font-size:11px;letter-spacing:0.14em;color:#a1a1aa;margin-top:8px;font-weight:600;">RISK: ${riskScore}</div>
            </div>
          </td></tr></table>

          <!-- Pills -->
          <div style="margin-top:24px;">
            <span style="display:inline-block;margin:3px;padding:5px 12px;border-radius:999px;background:#18181b;border:1px solid #27272a;font-size:12px;color:#d4d4d8;">${shownUrl}</span>${
              opts.pagesScanned && opts.pagesScanned > 0
                ? `<span style="display:inline-block;margin:3px;padding:5px 12px;border-radius:999px;background:#0c1a2e;border:1px solid #1e3a5f;font-size:12px;color:#60a5fa;">Scanned ${opts.pagesScanned} ${opts.pagesScanned === 1 ? "page" : "pages"}</span>`
                : ""
            }
          </div>

          <h1 style="margin:18px 0 0;font-family:${display};font-size:32px;line-height:1.15;font-weight:700;color:#fafafa;letter-spacing:-0.5px;">Security Report</h1>
          <p style="margin:12px auto 0;max-width:460px;font-size:15px;line-height:1.65;color:#a1a1aa;">${escapeHtml(summaryText)}</p>
          ${opts.changesLine ? `<p style="margin:10px auto 0;max-width:460px;font-size:13px;line-height:1.5;color:#22c55e;">${escapeHtml(opts.changesLine)}</p>` : ""}
          ${dots ? `<div style="margin-top:14px;">${dots}</div>` : ""}
        </td></tr>

        <!-- Numbers, styled like the monitor cards -->
        <tr><td style="padding:14px 0 0;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
            <td width="33%" style="padding:0 6px 0 0;">
              <div style="background:#18181b;border:1px solid #27272a;border-radius:16px;padding:18px 8px;text-align:center;">
                <div style="font-family:${display};font-size:26px;font-weight:700;color:${gradeColor};line-height:1.1;">${riskScore}<span style="font-size:15px;color:#71717a;">/100</span></div>
                <div style="font-size:12px;color:#a1a1aa;margin-top:6px;">Risk score</div>
              </div>
            </td>
            <td width="33%" style="padding:0 ${testsTile ? 6 : 0}px 0 6px;">
              <div style="background:#18181b;border:1px solid #27272a;border-radius:16px;padding:18px 8px;text-align:center;">
                <div style="font-family:${display};font-size:26px;font-weight:700;color:#fafafa;line-height:1.1;">${totalVulns}</div>
                <div style="font-size:12px;color:#a1a1aa;margin-top:6px;">${totalVulns === 1 ? "Finding" : "Findings"}</div>
              </div>
            </td>
            ${testsTile}
          </tr></table>
        </td></tr>

        <!-- Primary action -->
        <tr><td style="padding:22px 0 0;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
            <td align="center" style="border-radius:12px;background:#22c55e;box-shadow:0 0 24px rgba(34,197,94,0.25);">
              <a href="${href}" style="display:block;padding:16px 24px;font-family:${display};font-size:16px;font-weight:700;color:#09090b;text-decoration:none;border-radius:12px;">View Full Report &rarr;</a>
            </td>
          </tr></table>
          <p style="margin:14px 0 0;font-size:13px;line-height:1.6;color:#a1a1aa;text-align:center;">Every finding with its evidence and fix, a prompt for your AI editor, OWASP and compliance mapping, and a PDF download.</p>
          ${coverageNote}
        </td></tr>

        <!-- Footer -->
        <tr><td style="padding:28px 2px 0;font-size:12px;line-height:1.7;color:#71717a;text-align:center;">
          <span style="font-family:${display};font-weight:700;color:#a1a1aa;">SecScan</span> &middot; Security scanning for apps built fast.<br>
          You're receiving this because you ran a scan.
          <a href="${origin}/settings" style="color:#a1a1aa;text-decoration:underline;">Email settings</a>
          &middot;
          <a href="mailto:hello@secscan.us" style="color:#a1a1aa;text-decoration:underline;">hello@secscan.us</a>
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

  // No userId here to check an opt-out against, but the suppression list is
  // keyed on the address, so a bounced or complained-about recipient is still
  // honoured.
  if (await isSuppressed(opts.toEmail, "bulk")) {
    console.warn("[mailer] Skipping report-ready email — address is suppressed");
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
        subject: `Your SecScan.us report is ready — Grade ${opts.grade} for ${opts.targetUrl}`,
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
