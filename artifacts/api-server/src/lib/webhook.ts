/**
 * Outbound webhook delivery utility.
 * Sends Slack-compatible JSON payloads to user-configured webhook URLs.
 * Compatible with Slack, Discord (/slack endpoint), and Teams incoming webhooks.
 * Retries once on non-2xx response.
 */

import { logger } from "./logger";
import { checkHostname } from "./ssrfGuard";
import { strictDispatcher } from "./pinnedDispatcher";
import { APP_DOMAIN } from "./appOrigin";
import { notificationPrefs, shouldNotify, type AlertKind } from "./notificationPrefs";

// ── SSRF guard ────────────────────────────────────────────────────────────────
// Host rules live in ssrfGuard.ts, shared with the scan-target path so the two
// copies of this control can't drift. The https-only rule stays here: it is a
// webhook concern (an auth token must not leave in cleartext), not a host one.

async function isWebhookUrlSafe(rawUrl: string): Promise<boolean> {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:") return false;
    const { ok: safe } = await checkHostname(url.hostname);
    return safe;
  } catch {
    return false;
  }
}

export type WebhookEventType =
  | "cve_alert"
  | "regression_detected"
  | "cert_expiry"
  | "scan_complete"
  // Raised by the hourly pulse check, which sees things a scan every fortnight
  // cannot: an outage, or a security header that quietly went away.
  | "site_down"
  | "site_recovered"
  | "security_drift";

export interface WebhookPayload {
  event: WebhookEventType;
  targetUrl: string;
  subscriptionId: string;
  timestamp: string;
  data: Record<string, unknown>;
}

/** Drift kinds are stored as slugs; nobody wants to read "hsts_weakened" in Slack. */
export function describeDriftKind(kind: string): string {
  switch (kind) {
    case "header_removed":    return "Security header removed";
    case "hsts_weakened":     return "HSTS weakened";
    case "final_url_changed": return "Redirect target changed";
    case "tls_downgrade":     return "HTTPS downgraded to HTTP";
    default:                  return kind;
  }
}

function buildSlackBody(payload: WebhookPayload): Record<string, unknown> {
  const { event, targetUrl, data } = payload;

  const eventLabels: Record<WebhookEventType, string> = {
    cve_alert: "⚠️ CVE Alert",
    regression_detected: "🔴 Security Regression Detected",
    cert_expiry: "🔒 TLS Certificate Expiring",
    scan_complete: "✅ Security Scan Complete",
    site_down: "🛑 Site Unreachable",
    site_recovered: "✅ Site Back Online",
    security_drift: "🔍 Security Configuration Changed",
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

  if (event === "site_down") {
    if (data.failureReason) attachmentFields.push({ title: "Reason", value: String(data.failureReason), short: false });
    if (data.consecutiveFailures != null) {
      attachmentFields.push({ title: "Failed checks", value: String(data.consecutiveFailures), short: true });
    }
  }

  if (event === "site_recovered" && data.httpStatus != null) {
    attachmentFields.push({ title: "Status", value: `HTTP ${data.httpStatus}`, short: true });
  }

  if (event === "security_drift" && Array.isArray(data.changes)) {
    const changes = data.changes as Array<{ kind: string; detail: string; severity: string }>;
    attachmentFields.push({
      title: `${changes.length} change${changes.length > 1 ? "s" : ""} detected`,
      value: changes
        .slice(0, 5)
        .map((c) => `*${describeDriftKind(c.kind)}* — ${c.detail} (${c.severity})`)
        .join("\n"),
      short: false,
    });
  }

  const color = event === "cve_alert" || event === "regression_detected" || event === "site_down" ? "danger"
    : event === "cert_expiry" || event === "security_drift" ? "warning"
    : "good";

  return {
    text: `*${label}* for \`${domain}\``,
    attachments: [
      {
        color,
        fallback: `${label} for ${domain}`,
        fields: attachmentFields,
        footer: `SecScan · ${APP_DOMAIN}`,
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
    // The SSRF check and this connection resolve the name separately; this opens the socket only
    // to an address vetted at connect time, so a rebinding record cannot slip through.
    dispatcher: strictDispatcher,
  } as RequestInit);
  return res.ok;
}

/**
 * Fire a Slack-compatible webhook. Retries once on failure.
 * Silently logs errors — never throws.
 */
/**
 * Webhook events map one-to-one onto notification kinds, so the kind is
 * derived rather than passed — one less argument a caller can get wrong, and
 * adding an event type will not compile until it is classified here.
 */
const EVENT_TO_KIND: Record<WebhookEventType, AlertKind> = {
  cve_alert: "cve",
  regression_detected: "regression",
  cert_expiry: "cert_expiry",
  scan_complete: "scan_complete",
  site_down: "availability",
  site_recovered: "availability",
  security_drift: "drift",
};

export async function fireWebhook(
  webhookUrl: string,
  event: WebhookEventType,
  targetUrl: string,
  subscriptionId: string,
  data: Record<string, unknown>,
  // Required, deliberately. Webhooks honoured no preference at all before
  // this, and an optional argument is one a future call site forgets — which
  // would silently reintroduce exactly that.
  notify: { userId: string; severity?: string | null },
): Promise<void> {
  // Do NOT log the webhook URL — it may contain secret tokens in the path/query.
  const log = logger.child({ event, subscriptionId });

  // Checked before the SSRF guard: no point resolving DNS for a delivery the
  // user has asked not to receive. Note the email master switch does NOT
  // apply here — see notificationPrefs.ts.
  const prefs = await notificationPrefs(notify.userId);
  if (!shouldNotify(prefs, { kind: EVENT_TO_KIND[event], severity: notify.severity, channel: "webhook" })) {
    log.info("Webhook skipped — user's notification preferences");
    return;
  }

  const safe = await isWebhookUrlSafe(webhookUrl);
  if (!safe) {
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
