import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { PATH_PROBES } from "./crawler-data.js";

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

// ─── Found by the 20-target live false-positive sweep, 2026-09-09 ────────────

describe("PHP error detection needs a PHP shape, not an English word", () => {
  // The pattern was /Parse error:|Fatal error:|Warning:|Notice:/ — a bare word
  // and a colon. linkedin.com, which is Java and serves JSESSIONID, was
  // reported as leaking a PHP error from its 404 page.
  const PHP_ERROR =
    /(?:Parse error:\s*syntax error|Fatal error:\s*Uncaught\b|(?:Warning|Notice|Deprecated):\s+(?:Undefined\s+(?:variable|index|offset|array key|property)\b|\w+\(\):))/m;

  it("matches what PHP actually emits", () => {
    for (const t of [
      "Parse error: syntax error, unexpected T_STRING in x",
      "Fatal error: Uncaught Error: Call to undefined function foo()",
      "Warning: mysqli_connect(): Access denied for user",
      "Notice: Undefined variable: config",
      "Notice: Undefined index: id",
      "Deprecated: strlen(): Passing null is deprecated",
    ]) {
      expect(PHP_ERROR.test(t)).toBe(true);
    }
  });

  it("does not match ordinary page copy", () => {
    for (const t of [
      "Privacy Notice: we use cookies to improve your experience",
      "Legal Notice: all rights reserved",
      "Warning: this action cannot be undone",
      "Notice: scheduled maintenance on Sunday",
      "Important Notice: read this before continuing",
      "Cookie Notice: manage your preferences",
    ]) {
      expect(PHP_ERROR.test(t)).toBe(false);
    }
  });
});

describe("a GraphQL endpoint is a JSON response, not a page mentioning GraphQL", () => {
  // The crawler's check was /"__schema"|"__type"|graphql|GraphQL/i against the
  // whole body, so nytimes.com's HTML — which names graphql in a script URL —
  // became "GraphQL Endpoint Exposed". Mirrors graphqlProbe.ts's structural rule.
  // The real validate, not a copy of it: a duplicate here could keep passing
  // while the module it is meant to pin behaves differently.
  const probe = PATH_PROBES.find((p) => p.suffix === "/graphql")!;
  const validate = (body: string, ct: string): boolean => probe.validate(body, ct, 200);

  it("accepts a real GraphQL response", () => {
    expect(validate('{"data":{"__typename":"Query"}}', "application/json")).toBe(true);
    expect(validate('{"errors":[{"message":"GET query missing"}]}', "application/json")).toBe(true);
    expect(validate('{"data":{"__schema":{"types":[]}}}', "application/json")).toBe(true);
  });

  it("still accepts an interactive playground served as HTML", () => {
    // A console at /graphql IS an exposure, so the fix must not reject all HTML
    // — it has to require a playground fingerprint rather than the bare word.
    for (const page of [
      "<html>GraphQL Playground</html>",
      '<html><head><link rel="stylesheet" href="//unpkg.com/graphiql.min.css"></head></html>',
      '<html><body><div id="graphiql">Loading</div></body></html>',
      "<html><body>Apollo Sandbox</body></html>",
    ]) {
      expect(validate(page, "text/html")).toBe(true);
    }
  });

  it("rejects an HTML page that merely mentions graphql", () => {
    const page = '<!doctype html><html><head><script src="/_next/graphql-client.js"></script></head><body>GraphQL powers our API</body></html>';
    expect(validate(page, "text/html; charset=UTF-8")).toBe(false);
  });

  it("rejects JSON that is not GraphQL-shaped", () => {
    expect(validate('{"status":"ok","graphql":true}', "application/json")).toBe(false);
    expect(validate('{"errors":[]}', "application/json")).toBe(false);
    expect(validate("not json at all", "application/json")).toBe(false);
  });
});
