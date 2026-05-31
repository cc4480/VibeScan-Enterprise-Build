/**
 * Outbound webhook delivery utility.
 * Sends Slack-compatible JSON payloads to user-configured webhook URLs.
 * Compatible with Slack, Discord (/slack endpoint), and Teams incoming webhooks.
 * Retries once on non-2xx response.
 */

import { logger } from "./logger";

export type WebhookEventType =
  | "cve_alert"
  | "regression_detected"
  | "cert_expiry"
  | "scan_complete";

export interface WebhookPayload {
  event: WebhookEventType;
  targetUrl: string;
  subscriptionId: string;
  timestamp: string;
  data: Record<string, unknown>;
}

function buildSlackBody(payload: WebhookPayload): Record<string, unknown> {
  const { event, targetUrl, data } = payload;

  const eventLabels: Record<WebhookEventType, string> = {
    cve_alert: "⚠️ CVE Alert",
    regression_detected: "🔴 Security Regression Detected",
    cert_expiry: "🔒 TLS Certificate Expiring",
    scan_complete: "✅ Security Scan Complete",
  };

  const label = eventLabels[event] ?? event;
  const domain = (() => { try { return new URL(targetUrl).hostname; } catch { return targetUrl; } })();

  const attachmentFields: Array<{ title: string; value: string; short: boolean }> = [];

  if (event === "cve_alert" && Array.isArray(data.cves)) {
    const cves = data.cves as Array<{ cveId: string; severity: string; affectedTech: string; epssPercentile?: number }>;
    attachmentFields.push({
      title: `${cves.length} CVE${cves.length > 1 ? "s" : ""} matched`,
      value: cves.slice(0, 3).map((c) => {
        const epss = c.epssPercentile != null ? ` (EPSS ${Math.round(c.epssPercentile * 100)}th %ile)` : "";
        return `*${c.cveId}* — ${c.severity}${epss} — ${c.affectedTech}`;
      }).join("\n") + (cves.length > 3 ? `\n_+${cves.length - 3} more_` : ""),
      short: false,
    });
  }

  if (event === "regression_detected" && Array.isArray(data.regressions)) {
    const regs = data.regressions as Array<{ checkTitle: string; severity: string }>;
    attachmentFields.push({
      title: `${regs.length} regression${regs.length > 1 ? "s" : ""}`,
      value: regs.slice(0, 5).map((r) => `*${r.checkTitle}* (${r.severity})`).join("\n"),
      short: false,
    });
  }

  if (event === "cert_expiry") {
    attachmentFields.push({
      title: "Days remaining",
      value: String(data.daysRemaining ?? "?"),
      short: true,
    });
    if (data.expiryDate) {
      attachmentFields.push({
        title: "Expiry date",
        value: new Date(data.expiryDate as string).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
        short: true,
      });
    }
  }

  if (event === "scan_complete") {
    if (data.grade) attachmentFields.push({ title: "Grade", value: String(data.grade), short: true });
    if (data.riskScore != null) attachmentFields.push({ title: "Risk Score", value: `${data.riskScore}/100`, short: true });
    if (data.reportUrl) attachmentFields.push({ title: "Report", value: String(data.reportUrl), short: false });
  }

  const color = event === "cve_alert" || event === "regression_detected" ? "danger"
    : event === "cert_expiry" ? "warning"
    : "good";

  return {
    text: `*${label}* for \`${domain}\``,
    attachments: [
      {
        color,
        fallback: `${label} for ${domain}`,
        fields: attachmentFields,
        footer: "Seclayer · seclayer.io",
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };
}

async function postWebhook(url: string, body: Record<string, unknown>): Promise<boolean> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  return res.ok;
}

/**
 * Fire a Slack-compatible webhook. Retries once on failure.
 * Silently logs errors — never throws.
 */
export async function fireWebhook(
  webhookUrl: string,
  event: WebhookEventType,
  targetUrl: string,
  subscriptionId: string,
  data: Record<string, unknown>,
): Promise<void> {
  const log = logger.child({ webhookUrl: webhookUrl.slice(0, 40) + "…", event, subscriptionId });

  const payload: WebhookPayload = {
    event,
    targetUrl,
    subscriptionId,
    timestamp: new Date().toISOString(),
    data,
  };

  const body = buildSlackBody(payload);

  try {
    const ok = await postWebhook(webhookUrl, body);
    if (!ok) {
      log.warn("Webhook returned non-2xx — retrying once");
      await new Promise((r) => setTimeout(r, 1000));
      const ok2 = await postWebhook(webhookUrl, body);
      if (!ok2) log.warn("Webhook retry also failed — giving up");
      else log.info("Webhook retry succeeded");
    } else {
      log.info("Webhook delivered");
    }
  } catch (err) {
    log.warn({ err }, "Webhook delivery error (non-fatal)");
  }
}
