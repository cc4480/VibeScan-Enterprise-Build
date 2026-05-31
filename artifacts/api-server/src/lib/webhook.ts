/**
 * Outbound webhook delivery utility.
 * Sends Slack-compatible JSON payloads to user-configured webhook URLs.
 * Compatible with Slack, Discord (/slack endpoint), and Teams incoming webhooks.
 * Retries once on non-2xx response.
 */

import { logger } from "./logger";
import * as net from "node:net";

// ── SSRF guard ────────────────────────────────────────────────────────────────

const PRIVATE_IP_PATTERNS = [
  /^127\./,           // loopback
  /^0\.0\.0\.0$/,
  /^10\./,            // RFC 1918
  /^172\.(1[6-9]|2\d|3[01])\./,  // RFC 1918
  /^192\.168\./,      // RFC 1918
  /^169\.254\./,      // link-local / AWS metadata
  /^100\.6[4-9]\.|^100\.[7-9]\d\.|^100\.1[01]\d\.|^100\.12[0-7]\./,  // CGNAT
  /^::1$/,
  /^fc[0-9a-f]{2}:/i,
  /^fd[0-9a-f]{2}:/i,
];

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "169.254.169.254",
  "metadata.internal",
  "metadata",
]);

/**
 * Returns false if the URL looks like it targets a private/internal address.
 * Performs hostname-level checks only (no DNS resolution) for speed and reliability.
 */
function isWebhookUrlSafe(rawUrl: string): boolean {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:" && url.protocol !== "http:") return false;
    const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
    if (BLOCKED_HOSTNAMES.has(hostname)) return false;
    // Reject literal IP addresses in private ranges
    if (net.isIP(hostname)) {
      return !PRIVATE_IP_PATTERNS.some((r) => r.test(hostname));
    }
    // Reject hostnames that resolve to .local or .internal TLDs
    if (hostname.endsWith(".local") || hostname.endsWith(".internal")) return false;
    return true;
  } catch {
    return false;
  }
}

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
  // redirect: "error" ensures any redirect response throws rather than silently following
  // to an attacker-controlled internal target (redirect-based SSRF bypass).
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
    redirect: "error",
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

  if (!isWebhookUrlSafe(webhookUrl)) {
    log.warn("Webhook URL blocked by SSRF guard — skipping delivery");
    return;
  }

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
