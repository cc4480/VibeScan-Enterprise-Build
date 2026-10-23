/**
 * Outbound webhook delivery utility.
 * Sends an alert to a user-configured webhook URL, written for the destination the URL points at (Slack, Discord, Teams,
 * or plain JSON; see webhookFormats.ts). Retries once on non-2xx response.
 */

import { logger } from "./logger";
import { checkHostname } from "./ssrfGuard";
import { strictDispatcher } from "./pinnedDispatcher";
import { renderWebhookBody, webhookDestination } from "./webhookFormats";
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

export { describeDriftKind } from "./webhookFormats";

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

/**
 * What happened to a delivery. Callers may ignore it (delivery is best effort and never throws); it is returned so the
 * outcome is observable without reading logs.
 */
export interface WebhookOutcome {
  status: "delivered" | "skipped_preferences" | "blocked_url" | "failed";
  /** Requests actually sent: 0 when skipped or blocked, 2 when the first was not accepted and was retried. */
  attempts: number;
}

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
): Promise<WebhookOutcome> {
  // Do NOT log the webhook URL — it may contain secret tokens in the path/query.
  const log = logger.child({ event, subscriptionId });

  // Checked before the SSRF guard: no point resolving DNS for a delivery the
  // user has asked not to receive. Note the email master switch does NOT
  // apply here — see notificationPrefs.ts.
  const prefs = await notificationPrefs(notify.userId);
  if (!shouldNotify(prefs, { kind: EVENT_TO_KIND[event], severity: notify.severity, channel: "webhook" })) {
    log.info("Webhook skipped — user's notification preferences");
    return { status: "skipped_preferences", attempts: 0 };
  }

  const safe = await isWebhookUrlSafe(webhookUrl);
  if (!safe) {
    log.warn("Webhook URL blocked by SSRF guard — skipping delivery");
    return { status: "blocked_url", attempts: 0 };
  }

  const payload: WebhookPayload = {
    event,
    targetUrl,
    subscriptionId,
    timestamp: new Date().toISOString(),
    data,
  };

  const body = renderWebhookBody(webhookDestination(webhookUrl), payload);

  let attempts = 0;
  try {
    attempts = 1;
    const ok = await postWebhook(webhookUrl, body);
    if (!ok) {
      log.warn("Webhook returned non-2xx — retrying once");
      await new Promise((r) => setTimeout(r, 1000));
      attempts = 2;
      const ok2 = await postWebhook(webhookUrl, body);
      if (!ok2) {
        log.warn("Webhook retry also failed — giving up");
        return { status: "failed", attempts };
      }
      log.info("Webhook retry succeeded");
      return { status: "delivered", attempts };
    }
    log.info("Webhook delivered");
    return { status: "delivered", attempts };
  } catch (err) {
    log.warn({ err }, "Webhook delivery error (non-fatal)");
    return { status: "failed", attempts };
  }
}
