import { describe, it, expect } from "vitest";
import { runNextjsProbe } from "./nextjsProbe.js";

function pageWithNextData(props: unknown): string {
  return `<html><body>
    <div id="__next"></div>
    <script id="__NEXT_DATA__" type="application/json">${JSON.stringify({
      props: { pageProps: props },
      buildId: "abc123",
    })}</script>
  </body></html>`;
}

describe("runNextjsProbe — real secrets still caught", () => {
  it("flags a live Stripe secret key", async () => {
    const html = pageWithNextData({ stripeKey: "sk_live_" + "a".repeat(30) });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.some((f) => /Stripe Live Secret Key/i.test(f.name))).toBe(true);
  });

  it("flags a real-looking database connection string", async () => {
    const html = pageWithNextData({
      dbUrl: "postgres://appuser:Xk9$mQp2vLz8@db.internal.example.com:5432/prod",
    });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.some((f) => /Database Connection String/i.test(f.name))).toBe(true);
  });

  it("flags a real AWS secret access key", async () => {
    const html = pageWithNextData({
      secretAccessKey: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD",
    });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.some((f) => /AWS Secret Access Key/i.test(f.name))).toBe(true);
  });
});

describe("runNextjsProbe — regression: placeholder values not flagged", () => {
  it("does not flag a 'connect your database' onboarding example with a placeholder password", async () => {
    // The exact false positive this exists to prevent: a setup wizard renders
    // its own example connection string into page props — "here's the format
    // we expect" — using a literal word like "password" or "changeme" as the
    // stand-in value. Format alone (postgres://user:pass@host) is identical
    // to a real leaked credential.
    const html = pageWithNextData({
      exampleConnectionString: "postgres://user:password@localhost:5432/mydb",
    });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.some((f) => /Database Connection String/i.test(f.name))).toBe(false);
  });

  it("does not flag the well-known AWS SDK example secret key from docs snippets", async () => {
    const html = pageWithNextData({
      docsSnippet: "secretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings.some((f) => /AWS Secret Access Key/i.test(f.name))).toBe(false);
  });

  it("stays quiet on a page with no __NEXT_DATA__ secrets at all", async () => {
    const html = pageWithNextData({ userName: "alice", theme: "dark" });
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings).toEqual([]);
  });

  it("stays quiet entirely on a non-Next.js page", async () => {
    const html = "<html><body>Just a plain page, no Next.js markers</body></html>";
    const findings = await runNextjsProbe("https://example.com", html);
    expect(findings).toEqual([]);
  });
});
