import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Regression tests for false positives found by scanning google.com.
 *
 * Each uses the values google.com actually returns, so the test fails if the
 * suppression is narrowed back to where it was.
 */

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

function respondWith(body: string, headers: Record<string, string>, status = 200) {
  globalThis.fetch = (async () =>
    new Response(body, { status, headers })) as typeof fetch;
}

describe("rate limiting behind a CDN", () => {
  beforeEach(() => vi.resetModules());

  it("does not claim google.com has no rate limiting", async () => {
    // google.com answers `Server: gws`. Only `gfe` was matched, so the most
    // rate-limited site on the internet was reported as having none.
    respondWith("<html></html>", { server: "gws" });
    const { checkRateLimiting } = await import("./probes.js");
    expect(await checkRateLimiting("https://www.google.com/")).toEqual([]);
  });

  it("still suppresses for the other Google frontends", async () => {
    for (const server of ["gfe", "ESF", "sffe", "Golfe2"]) {
      vi.resetModules();
      respondWith("<html></html>", { server });
      const { checkRateLimiting } = await import("./probes.js");
      expect(await checkRateLimiting("https://example.com/"), server).toEqual([]);
    }
  });

  it("still records a plain origin with no rate-limit signal", async () => {
    // The suppression must not have become a blanket amnesty.
    vi.resetModules();
    respondWith("<html></html>", { server: "nginx" });
    const { checkRateLimiting } = await import("./probes.js");
    const found = await checkRateLimiting("https://example.com/");
    expect(found).toHaveLength(1);
    expect(found[0]!.name).toBe("Rate Limiting Not Advertised in Response Headers");
  });

  it("records it as info, because header absence is not evidence of absence", async () => {
    // stripe.com sends no rate-limit headers at all and unquestionably rate
    // limits; across 30 sites this fired on 15. The check can see whether rate
    // limiting is ADVERTISED and nothing more, so it must not carry weight in
    // the grade — info scores 0 in computeRiskScore.
    vi.resetModules();
    respondWith("<html></html>", { server: "nginx" });
    const { checkRateLimiting } = await import("./probes.js");
    const found = await checkRateLimiting("https://example.com/");
    expect(found[0]!.severity).toBe("info");
    expect(found[0]!.cvssScore).toBe(0);
    expect(found[0]!.name).not.toMatch(/no rate limiting/i);
  });
});

describe("robots.txt sensitive-path disclosure", () => {
  beforeEach(() => vi.resetModules());

  it("does not flag public API and dashboard paths", async () => {
    // Real lines from google.com/robots.txt. These are documented public
    // endpoints; matching them on the substrings "/api/" and "dashboard"
    // produced a disclosure finding against google.com.
    respondWith(
      [
        "User-agent: *",
        "Disallow: /maps/api/js/",
        "Disallow: /maps/reserve/api/",
        "Disallow: /maps/reserve/partner-dashboard",
        "Disallow: /maps/api/staticmap",
      ].join("\n"),
      { "content-type": "text/plain" },
    );
    const { checkRobotsTxt } = await import("./probes.js");
    expect(await checkRobotsTxt("https://www.google.com/")).toEqual([]);
  });

  it("still flags paths that are genuinely not meant to be public", async () => {
    vi.resetModules();
    respondWith(
      ["User-agent: *", "Disallow: /admin/", "Disallow: /.env", "Disallow: /backup/"].join("\n"),
      { "content-type": "text/plain" },
    );
    const { checkRobotsTxt } = await import("./probes.js");
    const found = await checkRobotsTxt("https://example.com/");
    expect(found).toHaveLength(1);
    expect(found[0]!.name).toMatch(/Discloses Sensitive Application Paths/);
  });
});
