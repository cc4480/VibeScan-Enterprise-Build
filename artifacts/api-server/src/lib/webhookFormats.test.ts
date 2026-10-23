import { describe, it, expect } from "vitest";
import { webhookDestination, buildAlertContent, renderWebhookBody, type WebhookDestination } from "./webhookFormats";
import type { WebhookPayload } from "./webhook";

/**
 * An alert is written once and rendered for the destination the URL points at. These are pure functions, so the tests
 * call them directly.
 */

const payload = (event: WebhookPayload["event"], data: Record<string, unknown> = {}): WebhookPayload => ({
  event, targetUrl: "https://shop.example.com/", subscriptionId: "sub-1", timestamp: "2026-10-23T09:00:00.000Z", data,
});
const CVE = payload("cve_alert", {
  cves: [
    { cveId: "CVE-2026-0001", severity: "critical", affectedTech: "lodash 4.17.15", epssPercentile: 0.97 },
    { cveId: "CVE-2026-0002", severity: "high", affectedTech: "express 4.0.0" },
  ],
});

describe("webhookDestination: chosen from the URL", () => {
  const cases: Array<[string, WebhookDestination]> = [
    ["https://hooks.slack.com/services/T000/B000/XXXX", "slack"],
    ["https://hooks.slack-gov.com/services/T000/B000/XXXX", "slack"],
    ["https://discord.com/api/webhooks/123/abc", "discord"],
    ["https://discordapp.com/api/webhooks/123/abc", "discord"],
    ["https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x", "teams"],
    ["https://default123.04.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke", "teams"],
    ["https://contoso.webhook.office.com/webhookb2/abc", "teams_connector"],
    ["https://outlook.office.com/webhook/abc", "teams_connector"],
  ];
  it.each(cases)("%s is %s", (url, expected) => {
    expect(webhookDestination(url)).toBe(expected);
  });

  it("keeps Discord's Slack-compatible endpoint on Slack's format, which is what Discord users were told to use", () => {
    expect(webhookDestination("https://discord.com/api/webhooks/123/abc/slack")).toBe("slack");
    expect(webhookDestination("https://discord.com/api/webhooks/123/abc/slack/")).toBe("slack");
  });

  it("gives a host it does not know Slack's format, as every webhook got before destinations existed", () => {
    // Mattermost, Rocket.Chat and many in-house receivers accept it; changing it would silently break them.
    for (const url of ["https://chat.example.org/hooks/abc", "https://mattermost.corp.example/hooks/xyz", "https://hooks.zapier.com/hooks/catch/1/2"]) {
      expect(webhookDestination(url), url).toBe("slack");
    }
  });

  it("lets a #fragment choose, since a fragment is never sent over the network", () => {
    expect(webhookDestination("https://hooks.zapier.com/hooks/catch/1/2#json")).toBe("generic");
    expect(webhookDestination("https://chat.example.org/hooks/abc#discord")).toBe("discord");
    expect(webhookDestination("https://chat.example.org/hooks/abc#teams")).toBe("teams");
    expect(webhookDestination("https://chat.example.org/hooks/abc#teams-connector")).toBe("teams_connector");
    expect(webhookDestination("https://discord.com/api/webhooks/1/a#slack")).toBe("slack");
    expect(webhookDestination("https://discord.com/api/webhooks/1/a#JSON")).toBe("generic");
  });

  it("ignores a fragment it does not know, and a host that only looks like a known one", () => {
    expect(webhookDestination("https://hooks.zapier.com/x#whatever")).toBe("slack");
    expect(webhookDestination("https://discord.com.evil.example/api/webhooks/1/a")).toBe("slack");
    expect(webhookDestination("https://evil.example/hooks.slack.com")).toBe("slack");
    expect(webhookDestination("https://notdiscord.com/api/webhooks/1/a")).toBe("slack");
  });

  it("does not throw on a URL that will not parse", () => {
    expect(webhookDestination("not a url")).toBe("slack");
  });
});

describe("buildAlertContent", () => {
  it("names the site and the event, and marks a CVE alert as dangerous", () => {
    const c = buildAlertContent(CVE);
    expect(c.domain).toBe("shop.example.com");
    expect(c.label).toContain("CVE Alert");
    expect(c.tone).toBe("danger");
    expect(c.fields[0]!.title).toBe("2 CVEs matched");
    expect(c.fields[0]!.value).toContain("CVE-2026-0001");
    expect(c.fields[0]!.value).toContain("EPSS 97th %ile");
  });

  it("lists at most three CVEs and says how many more", () => {
    const cves = Array.from({ length: 5 }, (_, i) => ({ cveId: `CVE-2026-00${i}`, severity: "high", affectedTech: "x" }));
    const c = buildAlertContent(payload("cve_alert", { cves }));
    expect(c.fields[0]!.value).toContain("+2 more");
  });

  it("tones certificate expiry and drift as warnings, and a finished scan as good news", () => {
    expect(buildAlertContent(payload("cert_expiry", { daysRemaining: 6 })).tone).toBe("warning");
    expect(buildAlertContent(payload("security_drift", { changes: [] })).tone).toBe("warning");
    expect(buildAlertContent(payload("scan_complete", { grade: "A", riskScore: 12 })).tone).toBe("good");
    expect(buildAlertContent(payload("site_down", { failureReason: "timeout" })).tone).toBe("danger");
  });

  it("describes drift in words, not slugs", () => {
    const c = buildAlertContent(payload("security_drift", { changes: [{ kind: "hsts_weakened", detail: "max-age cut to 0", severity: "high" }] }));
    expect(c.fields[0]!.value).toContain("HSTS weakened");
    expect(c.fields[0]!.value).not.toContain("hsts_weakened");
  });

  it("falls back to the raw address when the site URL does not parse", () => {
    expect(buildAlertContent({ ...CVE, targetUrl: "not a url" }).domain).toBe("not a url");
  });
});

describe("renderWebhookBody", () => {
  it("slack: the same body every webhook has always received", () => {
    const body = renderWebhookBody("slack", CVE) as { text: string; attachments: Array<{ color: string; fields: unknown[]; footer: string; ts: number }> };
    expect(body.text).toBe("*⚠️ CVE Alert* for `shop.example.com`");
    expect(body.attachments[0]!.color).toBe("danger");
    expect(body.attachments[0]!.fields).toHaveLength(1);
    expect(body.attachments[0]!.footer).toMatch(/^SecScan · /);
    expect(body.attachments[0]!.ts).toBe(Math.floor(Date.parse("2026-10-23T09:00:00.000Z") / 1000));
  });

  it("discord: one embed with fields, Markdown bold, and no backticks in the title", () => {
    const body = renderWebhookBody("discord", CVE) as { embeds: Array<{ title: string; color: number; fields: Array<{ name: string; value: string; inline: boolean }>; timestamp: string }> };
    const e = body.embeds[0]!;
    expect(e.title).toBe("⚠️ CVE Alert — shop.example.com");
    expect(e.color).toBe(0xd32f2f);
    expect(e.fields[0]!.name).toBe("2 CVEs matched");
    expect(e.fields[0]!.value).toContain("**CVE-2026-0001**");
    expect(e.fields[0]!.value).not.toMatch(/(^|[^*])\*CVE/);
    expect(e.timestamp).toBe("2026-10-23T09:00:00.000Z");
  });

  it("discord: stays inside Discord's limits (25 fields, 1,024 characters a value, 256 a title)", () => {
    const long = "x".repeat(5_000);
    const c = renderWebhookBody("discord", payload("site_down", { failureReason: long, consecutiveFailures: 3 })) as { embeds: Array<{ title: string; fields: Array<{ value: string }> }> };
    for (const f of c.embeds[0]!.fields) expect(f.value.length).toBeLessThanOrEqual(1024);
    expect(c.embeds[0]!.title.length).toBeLessThanOrEqual(256);
    const manyChanges = Array.from({ length: 40 }, (_, i) => ({ kind: "header_removed", detail: `h${i}`, severity: "low" }));
    const d = renderWebhookBody("discord", payload("security_drift", { changes: manyChanges })) as { embeds: Array<{ fields: unknown[] }> };
    expect(d.embeds[0]!.fields.length).toBeLessThanOrEqual(25);
  });

  it("discord: never sends an empty field value, which Discord rejects", () => {
    const body = renderWebhookBody("discord", payload("scan_complete", { grade: "A" })) as { embeds: Array<{ fields: Array<{ value: string }> }> };
    for (const f of body.embeds[0]!.fields) expect(f.value.length).toBeGreaterThan(0);
  });

  it("teams (Workflows): an Adaptive Card inside a message, with the facts", () => {
    const body = renderWebhookBody("teams", CVE) as { type: string; attachments: Array<{ contentType: string; content: { type: string; version: string; body: Array<{ type: string; text?: string; color?: string; facts?: Array<{ title: string; value: string }> }> } }> };
    expect(body.type).toBe("message");
    const a = body.attachments[0]!;
    expect(a.contentType).toBe("application/vnd.microsoft.card.adaptive");
    expect(a.content.type).toBe("AdaptiveCard");
    const [title, facts] = a.content.body;
    expect(title!.text).toContain("shop.example.com");
    expect(title!.color).toBe("Attention");
    expect(facts!.type).toBe("FactSet");
    expect(facts!.facts![0]!.title).toBe("2 CVEs matched");
    expect(facts!.facts![0]!.value).toContain("**CVE-2026-0001**");
  });

  it("teams (Workflows): an alert with nothing to list sends no empty FactSet", () => {
    const body = renderWebhookBody("teams", payload("site_recovered")) as { attachments: Array<{ content: { body: Array<{ type: string }> } }> };
    expect(body.attachments[0]!.content.body.map((b) => b.type)).toEqual(["TextBlock", "TextBlock"]);
  });

  it("teams (Office 365 connector): a MessageCard with a theme colour and facts", () => {
    const body = renderWebhookBody("teams_connector", CVE) as { "@type": string; themeColor: string; summary: string; sections: Array<{ facts: Array<{ name: string; value: string }> }> };
    expect(body["@type"]).toBe("MessageCard");
    expect(body.themeColor).toBe("D32F2F");
    expect(body.summary).toBe("⚠️ CVE Alert for shop.example.com");
    expect(body.sections[0]!.facts[0]!.name).toBe("2 CVEs matched");
  });

  it("generic: structured fields a router can read, with the raw data and no chat markup", () => {
    const body = renderWebhookBody("generic", CVE);
    expect(body).toEqual({
      source: "secscan",
      event: "cve_alert",
      severity: "critical",
      site: "shop.example.com",
      targetUrl: "https://shop.example.com/",
      subscriptionId: "sub-1",
      timestamp: "2026-10-23T09:00:00.000Z",
      summary: "⚠️ CVE Alert for shop.example.com",
      data: CVE.data,
    });
  });

  it("generic: maps the tone onto critical, warning and info", () => {
    const sev = (e: WebhookPayload["event"]) => (renderWebhookBody("generic", payload(e)) as { severity: string }).severity;
    expect(sev("site_down")).toBe("critical");
    expect(sev("cert_expiry")).toBe("warning");
    expect(sev("scan_complete")).toBe("info");
  });

  it("every destination produces JSON that survives a round trip", () => {
    const all: WebhookDestination[] = ["slack", "discord", "teams", "teams_connector", "generic"];
    for (const d of all) {
      const body = renderWebhookBody(d, CVE);
      expect(JSON.parse(JSON.stringify(body)), d).toEqual(body);
    }
  });
});
