import { describe, it, expect } from "vitest";

describe("LINK_PREVIEW_AGENT", () => {
  it("matches the chat and link-preview fetchers", async () => {
    const { LINK_PREVIEW_AGENT } = await import("./oobServer");
    for (const ua of [
      "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
      "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
      "facebookexternalhit/1.1",
      "SkypeUriPreview Preview/0.5",
    ]) expect(LINK_PREVIEW_AGENT.test(ua)).toBe(true);
  });

  it("does not match an ordinary server-side HTTP client", async () => {
    const { LINK_PREVIEW_AGENT } = await import("./oobServer");
    for (const ua of ["python-requests/2.31", "node-fetch/1.0", "Go-http-client/1.1", "curl/8.4.0", "axios/1.6"])
      expect(LINK_PREVIEW_AGENT.test(ua)).toBe(false);
  });
});
