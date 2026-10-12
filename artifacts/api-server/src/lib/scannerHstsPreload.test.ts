import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// If anything here reached the scan target (the old redirect fallback did), it would go through scanFetch.
const scanFetchMock = vi.fn();
vi.mock("./http", () => ({ scanFetch: (...a: unknown[]) => scanFetchMock(...a) }));

import { isHstsPreloaded } from "./scannerHstsPreload";
import { transportFindings } from "./scannerTransportChecks";

/**
 * "Missing HSTS" must be reported for a site that sends no Strict-Transport-Security header and is not on the
 * preload list, whether or not http:// redirects to https://.
 *
 * Found by repeating a 50-site sweep: no site got the finding, though six verifiably send no header and are not
 * listed. The cause was a fallback that treated "http://<host>/ redirects to HTTPS" as proof of preloading, and a
 * hardcoded set of names "built into Chrome" of which 23 of 40 are not on Chromium's list.
 */

const status = (name: string, s: string) => ({ ok: true, json: async () => ({ name, status: s }) }) as Response;

let asked: string[];
function preloadApi(answers: Record<string, string>) {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    const domain = new URL(url).searchParams.get("domain")!;
    asked.push(domain);
    return status(domain, answers[domain] ?? "unknown");
  }));
}

beforeEach(() => {
  asked = [];
  scanFetchMock.mockReset();
  // The old fallback would have found a redirect to https here.
  scanFetchMock.mockResolvedValue({ status: 200, body: "", headers: {}, setCookies: [], finalUrl: "https://www.example-site.com/", redirected: true });
});
afterEach(() => vi.unstubAllGlobals());

describe("isHstsPreloaded", () => {
  it("is true only when hstspreload.org says the host is preloaded", async () => {
    preloadApi({ "github.com": "preloaded", "pending.example-site.com": "pending", "rejected.example-site.com": "rejected" });
    expect(await isHstsPreloaded("github.com")).toBe(true);
    expect(await isHstsPreloaded("pending.example-site.com")).toBe(false);
    expect(await isHstsPreloaded("rejected.example-site.com")).toBe(false);
    expect(await isHstsPreloaded("laravel.com")).toBe(false);
  });

  it("asks about the exact host, not the apex: a listed parent may not cover its subdomains", async () => {
    preloadApi({ "docs.github.com": "preloaded" });
    expect(await isHstsPreloaded("docs.github.com")).toBe(true);
    expect(await isHstsPreloaded("www.example-site.com")).toBe(false);
    expect(asked).toEqual(["docs.github.com", "www.example-site.com"]);
  });

  it("does not treat an http:// to https:// redirect as preloading", async () => {
    preloadApi({});
    expect(await isHstsPreloaded("www.example-site.com")).toBe(false);
    expect(scanFetchMock).not.toHaveBeenCalled();
  });

  it("no longer trusts names it used to hardcode as built into Chrome", async () => {
    preloadApi({});
    for (const h of ["www.microsoft.com", "www.apple.com", "www.linkedin.com", "www.shopify.com", "www.google.com", "box.com", "outlook.com"]) {
      expect(await isHstsPreloaded(h)).toBe(false);
    }
    expect(asked).toHaveLength(7);
  });

  it("answers false, so the finding is still raised, when the API is down, slow or odd", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("connect ETIMEDOUT"); }));
    expect(await isHstsPreloaded("www.example-site.com")).toBe(false);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) }) as unknown as Response));
    expect(await isHstsPreloaded("www.example-site.com")).toBe(false);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, json: async () => { throw new Error("not json"); } }) as unknown as Response));
    expect(await isHstsPreloaded("www.example-site.com")).toBe(false);
  });

  it("does not send an address or an internal name anywhere", async () => {
    preloadApi({});
    for (const h of ["127.0.0.1", "10.1.2.3", "::1", "localhost", "intranet", "build.corp", "api.internal", "printer.local", "site.test", ""]) {
      expect(await isHstsPreloaded(h)).toBe(false);
    }
    expect(asked).toEqual([]);
  });
});

describe("the Missing HSTS finding", () => {
  const ctx = (host: string, headers: Record<string, string> = {}) =>
    ({ finalUrl: `https://${host}/`, rawHeaders: headers, isHttps: true }) as never;
  const hstsFinding = (f: Array<{ name: string }>) => f.find((x) => /Missing HTTP Strict-Transport-Security/.test(x.name));

  it("is raised for a site with no header that is not preloaded, although http:// redirects to https://", async () => {
    preloadApi({});
    const f = await transportFindings(ctx("www.example-site.com"));
    expect(hstsFinding(f)).toBeDefined();
    expect((hstsFinding(f) as unknown as { severity: string }).severity).toBe("medium");
  });

  it("is raised when the preload API cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline"); }));
    expect(hstsFinding(await transportFindings(ctx("www.example-site.com")))).toBeDefined();
  });

  it("clean twin: not raised for a preloaded host", async () => {
    preloadApi({ "docs.github.com": "preloaded" });
    expect(hstsFinding(await transportFindings(ctx("docs.github.com")))).toBeUndefined();
  });

  it("clean twin: not raised when the header is there", async () => {
    preloadApi({});
    const f = await transportFindings(ctx("www.example-site.com", { "strict-transport-security": "max-age=31536000; includeSubDomains" }));
    expect(hstsFinding(f)).toBeUndefined();
    expect(asked).toEqual([]);
  });

  it("still reports a header whose max-age is short", async () => {
    preloadApi({});
    const f = await transportFindings(ctx("www.example-site.com", { "strict-transport-security": "max-age=300" }));
    expect(f.some((x) => x.name === "HSTS max-age Too Short")).toBe(true);
  });
});
