import { describe, it, expect } from "vitest";
import { seedCookieIssuesFromRoot, buildHeaderGapVulns, confirmHeaderGaps, redactCookieValue } from "./crawler.js";
import { checkPageCookies } from "./crawlerCookies";


describe("checkPageCookies reads flags from the attributes and skips cookies being cleared", () => {
  const PAGE = "https://example.com/account/login/";
  const run = (cookies: string[]) => checkPageCookies(cookies, PAGE, true, new Set(), "crawl");

  // Seen on pypi.org (2026-10-05): /account/login/ clears user_id__insecure with Max-Age=0 and an
  // expires in 1997. The root scan already skips such a cookie; the inner-page check did not, and
  // reported it as "Readable by JavaScript".
  it("does not report a cookie the server is clearing", () => {
    expect(run(["user_id__insecure=; Max-Age=0; Path=/; expires=Wed, 31-Dec-97 23:59:59 GMT"])).toEqual([]);
    expect(run(["theme=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"])).toEqual([]);
  });

  it("still reports the same cookie when it is being set, not cleared", () => {
    const f = run(["user_id__insecure=abc; Max-Age=3600; Path=/"]);
    expect(f.map((v) => v.name)).toContain("Non-Session Cookie Readable by JavaScript on Inner Page");
    expect(f.map((v) => v.name)).toContain("Non-Session Cookie Missing Secure Flag on Inner Page");
  });

  // A regex over the whole line matched the word in the cookie's NAME, so a cookie called
  // secure_pref with no Secure flag counted as secure and was never reported.
  it("does not treat the word 'secure' or 'httponly' in a cookie name as the flag", () => {
    const f = run(["secure_pref=1; Path=/", "httponly_hint=1; Path=/"]);
    expect(f.some((v) => v.name.includes("Missing Secure Flag") && String(v.evidence).includes("secure_pref"))).toBe(true);
    expect(f.some((v) => v.name.includes("Readable by JavaScript") && String(v.evidence).includes("httponly_hint"))).toBe(true);
  });

  it("reports nothing for a cookie carrying both flags", () => {
    expect(run(["lang=en; Path=/; Secure; HttpOnly; SameSite=Lax"])).toEqual([]);
  });

  it("seeding from the root ignores a cleared cookie and reads the name's flags correctly", () => {
    expect(seedCookieIssuesFromRoot(["old=; Max-Age=0; Path=/"]).size).toBe(0);
    const seen = seedCookieIssuesFromRoot(["secure_pref=1; Path=/"]);
    expect(seen.has("secure::secure_pref")).toBe(true);
  });
});

describe("header-gap evidence keeps the query string", () => {
  // Found by the 2026-09-10 re-scan. paypal.com links every internal page as
  // "…/giving?locale.x=en_US". That URL answers with a CSP carrying no
  // frame-ancestors; the bare "…/giving" answers with a DIFFERENT CSP that has
  // it. The crawl fetched the linked form and was right — but the evidence
  // printed only `new URL(p).pathname`, so verifying the finding the way the
  // false-positive audit requires led straight to the wrong URL and made a true
  // finding look false.
  const root = { hsts: true, csp: true, xfo: true, xcto: true, rp: true };

  it("prints the query that produced the observation", () => {
    const gap = new Map([
      ["xfo", ["https://www.paypal.com/us/digital-wallet/send-receive-money/giving?locale.x=en_US"]],
    ] as const);
    const [v] = buildHeaderGapVulns(root, gap as never, new Set());
    expect(v!.evidence).toContain("?locale.x=en_US");
    expect(v!.evidence).toContain("/us/digital-wallet/send-receive-money/giving");
  });

  it("still labels how the route was reached", () => {
    const probed = "https://example.com/dashboard?next=%2Fhome";
    const gap = new Map([["csp", [probed]]] as const);
    const [v] = buildHeaderGapVulns(root, gap as never, new Set([probed]));
    expect(v!.evidence).toContain("?next=%2Fhome");
    expect(v!.evidence).toContain("(probed)");
  });

  it("leaves a query-less route unchanged", () => {
    const gap = new Map([["rp", ["https://example.com/about"]]] as const);
    const [v] = buildHeaderGapVulns(root, gap as never, new Set());
    expect(v!.evidence).toContain("  • /about (crawled)");
    expect(v!.evidence).not.toContain("?");
  });

  it("says nothing when the root lacked the header itself", () => {
    // A gap is only a gap against a root that had it — otherwise it is the
    // site-wide "missing header" finding, reported elsewhere.
    const gap = new Map([["xfo", ["https://example.com/a?b=1"]]] as const);
    expect(buildHeaderGapVulns({ ...root, xfo: false }, gap as never, new Set())).toEqual([]);
  });
});

describe("redactCookieValue", () => {
  it("replaces the value and keeps every attribute", () => {
    expect(redactCookieValue("sid=abc123def456; Path=/; Secure; SameSite=Lax")).toBe(
      "sid=<redacted>; Path=/; Secure; SameSite=Lax",
    );
  });

  it("redacts a value that contains '=' padding, not just up to the first one", () => {
    // base64 values carry "=" inside them; splitting naively leaks the tail.
    const out = redactCookieValue("loid=Z0FBQUFBQnFydVhn==; Domain=.reddit.com; Secure");
    expect(out).toBe("loid=<redacted>; Domain=.reddit.com; Secure");
    expect(out).not.toContain("Z0FB");
  });

  it("handles a cookie with no attributes", () => {
    expect(redactCookieValue("token=verysecretvalue")).toBe("token=<redacted>");
  });

  it("leaves a malformed line alone rather than mangling it", () => {
    expect(redactCookieValue("not-a-cookie")).toBe("not-a-cookie");
  });

  it("does not leak the value of an empty-valued cookie's attributes", () => {
    expect(redactCookieValue("a=; Path=/")).toBe("a=<redacted>; Path=/");
  });
});

describe("confirmHeaderGaps", () => {
  const withCsp = { status: 200, headers: { "content-security-policy": "default-src 'self'" } };
  const withoutCsp = { status: 200, headers: { "content-type": "text/html" } };

  it("drops a gap the second request does not reproduce", async () => {
    // reddit answers the same path with a CSP on one request and none on the
    // next. One observation of that is unreproducible by whoever disputes it.
    const gap = new Map<"csp", string[]>([["csp", ["https://example.com/flaky"]]]);
    await confirmHeaderGaps(gap as never, async () => withCsp);
    expect(gap.get("csp")).toEqual([]);
  });

  it("keeps a gap that is still there on the retry", async () => {
    // reddit's /live, github's /healthz, cloudflare's locale routes.
    const gap = new Map<"csp", string[]>([["csp", ["https://example.com/live"]]]);
    await confirmHeaderGaps(gap as never, async () => withoutCsp);
    expect(gap.get("csp")).toEqual(["https://example.com/live"]);
  });

  it("keeps the original observation when the retry cannot be made", async () => {
    // Trading this false positive for a silent false negative is the worse deal.
    const gap = new Map<"csp", string[]>([["csp", ["https://example.com/a"]]]);
    await confirmHeaderGaps(gap as never, async () => null);
    expect(gap.get("csp")).toEqual(["https://example.com/a"]);
  });

  it("keeps the observation when the retry returns an error status", async () => {
    const gap = new Map<"csp", string[]>([["csp", ["https://example.com/a"]]]);
    await confirmHeaderGaps(gap as never, async () => ({ status: 503, headers: {} }));
    expect(gap.get("csp")).toEqual(["https://example.com/a"]);
  });

  it("confirms each path independently", async () => {
    const gap = new Map<"csp", string[]>([
      ["csp", ["https://example.com/flaky", "https://example.com/live"]],
    ]);
    await confirmHeaderGaps(gap as never, async (url) =>
      url.endsWith("/flaky") ? withCsp : withoutCsp,
    );
    expect(gap.get("csp")).toEqual(["https://example.com/live"]);
  });

  it("never adds a path that was not already a gap", async () => {
    const gap = new Map<"csp", string[]>([["csp", []]]);
    await confirmHeaderGaps(gap as never, async () => withoutCsp);
    expect(gap.get("csp")).toEqual([]);
  });

  it("checks each header against its own presence, not another's", async () => {
    // xfo is satisfied by frame-ancestors inside a CSP as well as by the header,
    // so a retry carrying only a CSP with frame-ancestors clears an xfo gap.
    const gap = new Map<"xfo", string[]>([["xfo", ["https://example.com/a"]]]);
    await confirmHeaderGaps(gap as never, async () => ({
      status: 200,
      headers: { "content-security-policy": "frame-ancestors 'none'" },
    }));
    expect(gap.get("xfo")).toEqual([]);
  });
});
