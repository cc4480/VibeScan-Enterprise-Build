/**
 * What an alert says, and how each kind of destination wants it written.
 *
 * One alert is built once (`buildAlertContent`) and rendered for the destination its URL points at: Slack, Discord,
 * Microsoft Teams (the Workflows webhook and the older Office 365 connector), or plain structured JSON for Zapier, n8n,
 * PagerDuty-style routers and in-house services that read fields instead of parsing chat text. The destination is chosen
 * from the URL alone, so nothing extra is stored.
 */
import { APP_DOMAIN } from "./appOrigin";
import type { WebhookEventType, WebhookPayload } from "./webhook";

export type WebhookDestination = "slack" | "discord" | "teams" | "teams_connector" | "generic";

export interface AlertField { title: string; value: string; short: boolean }
export type AlertTone = "danger" | "warning" | "good";
export interface AlertContent {
  /** "⚠️ CVE Alert" */
  label: string;
  /** The site's hostname. */
  domain: string;
  fields: AlertField[];
  tone: AlertTone;
}

const EVENT_LABELS: Record<WebhookEventType, string> = {
  cve_alert: "⚠️ CVE Alert",
  regression_detected: "🔴 Security Regression Detected",
  cert_expiry: "🔒 TLS Certificate Expiring",
  scan_complete: "✅ Security Scan Complete",
  site_down: "🛑 Site Unreachable",
  site_recovered: "✅ Site Back Online",
  security_drift: "🔍 Security Configuration Changed",
};

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

export function buildAlertContent(payload: WebhookPayload): AlertContent {
  const { event, targetUrl, data } = payload;
  const domain = (() => { try { return new URL(targetUrl).hostname; } catch { return targetUrl; } })();
  const fields: AlertField[] = [];

  if (event === "cve_alert" && Array.isArray(data.cves)) {
    const cves = data.cves as Array<{ cveId: string; severity: string; affectedTech: string; epssPercentile?: number }>;
    fields.push({
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
    fields.push({
      title: `${regs.length} regression${regs.length > 1 ? "s" : ""}`,
      value: regs.slice(0, 5).map((r) => `*${r.checkTitle}* (${r.severity})`).join("\n"),
      short: false,
    });
  }

  if (event === "cert_expiry") {
    fields.push({ title: "Days remaining", value: String(data.daysRemaining ?? "?"), short: true });
    if (data.expiryDate) {
      fields.push({
        title: "Expiry date",
        value: new Date(data.expiryDate as string).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
        short: true,
      });
    }
  }

  if (event === "scan_complete") {
    if (data.grade) fields.push({ title: "Grade", value: String(data.grade), short: true });
    if (data.riskScore != null) fields.push({ title: "Risk Score", value: `${data.riskScore}/100`, short: true });
    if (data.reportUrl) fields.push({ title: "Report", value: String(data.reportUrl), short: false });
  }

  if (event === "site_down") {
    if (data.failureReason) fields.push({ title: "Reason", value: String(data.failureReason), short: false });
    if (data.consecutiveFailures != null) fields.push({ title: "Failed checks", value: String(data.consecutiveFailures), short: true });
  }

  if (event === "site_recovered" && data.httpStatus != null) {
    fields.push({ title: "Status", value: `HTTP ${data.httpStatus}`, short: true });
  }

  if (event === "security_drift" && Array.isArray(data.changes)) {
    const changes = data.changes as Array<{ kind: string; detail: string; severity: string }>;
    fields.push({
      title: `${changes.length} change${changes.length > 1 ? "s" : ""} detected`,
      value: changes.slice(0, 5).map((c) => `*${describeDriftKind(c.kind)}* — ${c.detail} (${c.severity})`).join("\n"),
      short: false,
    });
  }

  const tone: AlertTone = event === "cve_alert" || event === "regression_detected" || event === "site_down" ? "danger"
    : event === "cert_expiry" || event === "security_drift" ? "warning"
    : "good";
  return { label: EVENT_LABELS[event] ?? event, domain, fields, tone };
}

// ── Which destination a URL is ────────────────────────────────────────────────

const FRAGMENTS: Record<string, WebhookDestination> = {
  slack: "slack", discord: "discord", teams: "teams", "teams-connector": "teams_connector", json: "generic",
};

/**
 * Which format a URL wants. A `#json` (or `#slack`, `#discord`, `#teams`, `#teams-connector`) on the end of the URL says
 * so outright; a URL fragment is never sent over the network, so it costs nothing and cannot leak. Otherwise the host
 * decides. A host this does not know gets Slack's format, as every webhook did before destinations existed: many
 * receivers (Mattermost, Rocket.Chat, Discord's own `/slack` endpoint) accept it, and changing it would silently break them.
 */
export function webhookDestination(rawUrl: string): WebhookDestination {
  let url: URL;
  try { url = new URL(rawUrl); } catch { return "slack"; }
  const forced = FRAGMENTS[url.hash.replace(/^#/, "").toLowerCase()];
  if (forced) return forced;
  const host = url.hostname.toLowerCase();
  const is = (domain: string) => host === domain || host.endsWith(`.${domain}`);
  if (is("hooks.slack.com") || is("hooks.slack-gov.com")) return "slack";
  // Discord's Slack-compatible endpoint (…/slack) wants Slack's body, which is what Discord users were told to use.
  if (is("discord.com") || is("discordapp.com")) return /\/(slack|github)\/?$/.test(url.pathname) ? "slack" : "discord";
  if (is("logic.azure.com") || is("powerplatform.com")) return "teams";
  if (is("webhook.office.com") || is("outlook.office.com") || is("outlook.office365.com")) return "teams_connector";
  return "slack";
}

// ── Renderers ─────────────────────────────────────────────────────────────────

/** The alert text marks bold with Slack's single asterisks; Discord and Teams read Markdown's double ones. */
const toMarkdown = (s: string) => s.replace(/\*([^*\n]+)\*/g, "**$1**");
const stripBackticks = (s: string) => s.replace(/`/g, "");

const COLORS: Record<AlertTone, { slack: string; hex: string; int: number }> = {
  danger: { slack: "danger", hex: "D32F2F", int: 0xd32f2f },
  warning: { slack: "warning", hex: "F9A825", int: 0xf9a825 },
  good: { slack: "good", hex: "2E7D32", int: 0x2e7d32 },
};

export function slackBody(c: AlertContent, tsSeconds: number): Record<string, unknown> {
  return {
    text: `*${c.label}* for \`${c.domain}\``,
    attachments: [{
      color: COLORS[c.tone].slack,
      fallback: `${c.label} for ${c.domain}`,
      fields: c.fields,
      footer: `SecScan · ${APP_DOMAIN}`,
      ts: tsSeconds,
    }],
  };
}

export function discordBody(c: AlertContent, isoTimestamp: string): Record<string, unknown> {
  return {
    username: "SecScan",
    embeds: [{
      title: stripBackticks(`${c.label} — ${c.domain}`).slice(0, 256),
      color: COLORS[c.tone].int,
      // Discord caps an embed at 25 fields and a field value at 1,024 characters.
      fields: c.fields.slice(0, 25).map((f) => ({ name: f.title.slice(0, 256), value: toMarkdown(f.value).slice(0, 1024) || "—", inline: f.short })),
      footer: { text: `SecScan · ${APP_DOMAIN}` },
      timestamp: isoTimestamp,
    }],
  };
}

/** Teams' Workflows ("Post to a channel when a webhook request is received") takes an Adaptive Card in a message. */
export function teamsBody(c: AlertContent): Record<string, unknown> {
  const accent = { danger: "Attention", warning: "Warning", good: "Good" }[c.tone];
  return {
    type: "message",
    attachments: [{
      contentType: "application/vnd.microsoft.card.adaptive",
      contentUrl: null,
      content: {
        $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
        type: "AdaptiveCard",
        version: "1.4",
        body: [
          { type: "TextBlock", text: `${c.label} — ${c.domain}`, weight: "Bolder", size: "Medium", color: accent, wrap: true },
          ...(c.fields.length
            ? [{ type: "FactSet", facts: c.fields.map((f) => ({ title: f.title, value: toMarkdown(f.value) })) }]
            : []),
          { type: "TextBlock", text: `SecScan · ${APP_DOMAIN}`, isSubtle: true, size: "Small", wrap: true },
        ],
      },
    }],
  };
}

/** The older Office 365 connector webhook, still in use on many channels, takes a MessageCard. */
export function teamsConnectorBody(c: AlertContent): Record<string, unknown> {
  return {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    summary: stripBackticks(`${c.label} for ${c.domain}`),
    themeColor: COLORS[c.tone].hex,
    title: `${c.label} — ${c.domain}`,
    sections: [{
      facts: c.fields.map((f) => ({ name: f.title, value: toMarkdown(f.value) })),
      text: `SecScan · ${APP_DOMAIN}`,
      markdown: true,
    }],
  };
}

/** Everything a router needs as fields: the event, the site and the raw data, plus the text a person would read. */
export function genericBody(payload: WebhookPayload, c: AlertContent): Record<string, unknown> {
  return {
    source: "secscan",
    event: payload.event,
    severity: c.tone === "danger" ? "critical" : c.tone === "warning" ? "warning" : "info",
    site: c.domain,
    targetUrl: payload.targetUrl,
    subscriptionId: payload.subscriptionId,
    timestamp: payload.timestamp,
    summary: stripBackticks(`${c.label} for ${c.domain}`),
    data: payload.data,
  };
}

export function renderWebhookBody(destination: WebhookDestination, payload: WebhookPayload): Record<string, unknown> {
  const content = buildAlertContent(payload);
  switch (destination) {
    case "slack": return slackBody(content, Math.floor(Date.parse(payload.timestamp) / 1000) || Math.floor(Date.now() / 1000));
    case "discord": return discordBody(content, payload.timestamp);
    case "teams": return teamsBody(content);
    case "teams_connector": return teamsConnectorBody(content);
    default: return genericBody(payload, content);
  }
}
