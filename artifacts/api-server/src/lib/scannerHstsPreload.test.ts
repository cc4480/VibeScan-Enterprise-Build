import { describe, it, expect } from "vitest";
import { useHstsPreloadStub } from "./hstsPreloadStub.testkit";
import { isHstsPreloaded } from "./scannerHstsPreload";
import { transportFindings } from "./scannerTransportChecks";

// The preload API is a real HTTP server on loopback (lib/hstsPreloadStub.testkit.ts); which hosts it lists is set per test.
const api = await useHstsPreloadStub();

/**
 * "Missing HSTS" must be reported for a site that sends no Strict-Transport-Security header and is not on the
 * preload list, whether or not http:// redirects to https://.
 *
 * Found by repeating a 50-site sweep: no site got the finding, though six verifiably send no header and are not
 * listed. The cause was a fallback that treated "http://<host>/ redirects to HTTPS" as proof of preloading, and a
 * hardcoded set of names "built into Chrome" of which 23 of 40 are not on Chromium's list.
 *
 * The fallback itself (a request to the scan target) is gone: nothing here is served by a target, and the check
 * only ever asks the preload API.
 */

describe("isHstsPreloaded", () => {
  it("is true only when hstspreload.org says the host is preloaded", async () => {
    api.statuses.set("github.com", "preloaded");
    api.statuses.set("pending.example-site.com", "pending");
    api.statuses.set("rejected.example-site.com", "rejected");
    expect(await isHstsPreloaded("github.com")).toBe(true);
    expect(await isHstsPreloaded("pending.example-site.com")).toBe(false);
    expect(await isHstsPreloaded("rejected.example-site.com")).toBe(false);
    expect(await isHstsPreloaded("laravel.com")).toBe(false);
  });

  it("asks about the exact host, not the apex: a listed parent may not cover its subdomains", async () => {
    api.statuses.set("docs.github.com", "preloaded");
    expect(await isHstsPreloaded("docs.github.com")).toBe(true);
    expect(await isHstsPreloaded("www.example-site.com")).toBe(false);
    expect(api.asked).toEqual(["docs.github.com", "www.example-site.com"]);
  });

  it("no longer trusts names it used to hardcode as built into Chrome", async () => {
    for (const h of ["www.microsoft.com", "www.apple.com", "www.linkedin.com", "www.shopify.com", "www.google.com", "box.com", "outlook.com"]) {
      expect(await isHstsPreloaded(h)).toBe(false);
    }
    expect(api.asked).toHaveLength(7);
  });

  it("answers false, so the finding is still raised, when the API is down, slow or odd", async () => {
    for (const mode of ["drop", "unavailable", "garbage"] as const) {
      api.mode = mode;
      expect(await isHstsPreloaded("www.example-site.com")).toBe(false);
    }
  });

  it("does not send an address or an internal name anywhere", async () => {
    for (const h of ["127.0.0.1", "10.1.2.3", "::1", "localhost", "intranet", "build.corp", "api.internal", "printer.local", "site.test", ""]) {
      expect(await isHstsPreloaded(h)).toBe(false);
    }
    expect(api.asked).toEqual([]);
  });
});

describe("the Missing HSTS finding", () => {
  const ctx = (host: string, headers: Record<string, string> = {}) =>
    ({ finalUrl: `https://${host}/`, rawHeaders: headers, isHttps: true }) as never;
  const hstsFinding = (f: Array<{ name: string }>) => f.find((x) => /Missing HTTP Strict-Transport-Security/.test(x.name));

  it("is raised for a site with no header that is not preloaded, although http:// redirects to https://", async () => {
    const f = await transportFindings(ctx("www.example-site.com"));
    expect(hstsFinding(f)).toBeDefined();
    expect((hstsFinding(f) as unknown as { severity: string }).severity).toBe("medium");
  });

  it("is raised when the preload API cannot be reached", async () => {
    api.mode = "drop";
    expect(hstsFinding(await transportFindings(ctx("www.example-site.com")))).toBeDefined();
  });

  it("clean twin: not raised for a preloaded host", async () => {
    api.statuses.set("docs.github.com", "preloaded");
    expect(hstsFinding(await transportFindings(ctx("docs.github.com")))).toBeUndefined();
  });

  it("clean twin: not raised when the header is there", async () => {
    const f = await transportFindings(ctx("www.example-site.com", { "strict-transport-security": "max-age=31536000; includeSubDomains" }));
    expect(hstsFinding(f)).toBeUndefined();
    expect(api.asked).toEqual([]);
  });

  it("still reports a header whose max-age is short", async () => {
    const f = await transportFindings(ctx("www.example-site.com", { "strict-transport-security": "max-age=300" }));
    expect(f.some((x) => x.name === "HSTS max-age Too Short")).toBe(true);
  });
});
