import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// scanFetch (the hostname body check) is mocked per-test; the DoH CNAME lookup
// uses global fetch, stubbed below.
const scanFetchMock = vi.fn();
vi.mock("./http.js", () => ({ scanFetch: (...a: unknown[]) => scanFetchMock(...a) }));

import { checkSubdomainTakeover } from "./subdomainTakeover.js";

function doh(cname: string): Response {
  return new Response(JSON.stringify({ Status: 0, Answer: [{ name: "x", type: 5, TTL: 60, data: cname }] }), {
    status: 200,
    headers: { "content-type": "application/dns-json" },
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async () => doh("reddit.map.fastly.net")));
  scanFetchMock.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

describe("checkSubdomainTakeover — Host-routing false positive", () => {
  it("does NOT flag a live Fastly-fronted site whose hostname serves real content", async () => {
    // The exact www.reddit.com false positive: the CNAME points to
    // *.fastly.net, but the real hostname serves the real site. The buggy
    // version fetched the raw CNAME target, which returns Fastly's
    // "unknown domain" error and looked like a takeover.
    scanFetchMock.mockResolvedValue({ status: 200, body: "<!doctype html><html><body>Welcome to Reddit</body></html>" });

    const findings = await checkSubdomainTakeover("https://www.reddit.com");
    expect(findings).toEqual([]);
  });

  it("STILL flags a genuinely dangling CNAME whose hostname returns the provider's unclaimed error", async () => {
    scanFetchMock.mockResolvedValue({
      status: 404,
      body: "Fastly error: unknown domain: abandoned.example.com. Please check that this domain has been added to a service.",
    });

    const findings = await checkSubdomainTakeover("https://abandoned.example.com");
    expect(findings.length).toBe(1);
    expect(findings[0]!.name).toMatch(/Subdomain Takeover/);
    // Fastly is "Not vulnerable" in can-i-take-over-xyz: reported only as an unverified candidate.
    expect(findings[0]!.name).toContain("Unverified");
    expect(findings[0]!.severity).toBe("medium");
  });

  it("fetches the hostname, never the raw CNAME target", async () => {
    scanFetchMock.mockResolvedValue({ status: 200, body: "real site" });
    await checkSubdomainTakeover("https://www.reddit.com");
    // every scanFetch call must target the hostname, not *.fastly.net
    for (const call of scanFetchMock.mock.calls) {
      expect(String(call[0])).toContain("www.reddit.com");
      expect(String(call[0])).not.toContain("fastly.net");
    }
  });
});

describe("checkSubdomainTakeover — live hosts that merely CNAME to a provider", () => {
  const cnameTo = (target: string) => vi.stubGlobal("fetch", vi.fn(async () => doh(target)));
  const site = (host: string) => checkSubdomainTakeover(`https://${host}`);

  it("does NOT flag a live minified Netlify page that mentions netlify and 404 on one line", async () => {
    cnameTo("app.netlify.app");
    scanFetchMock.mockResolvedValue({
      status: 200,
      body: '<html><script>/* built on netlify */var e="404";</script><body>Welcome</body></html>',
    });
    expect(await site("www.example.com")).toEqual([]);
  });

  it("does NOT flag a live Fly.io API whose root answers 404 Not Found with a JSON body", async () => {
    cnameTo("api.fly.dev");
    scanFetchMock.mockResolvedValue({ status: 200, body: "404 Not Found" });
    expect(await site("api.example.com")).toEqual([]);
  });

  it("does NOT flag a Vercel API-only project whose route answers 404: NOT_FOUND", async () => {
    cnameTo("api.vercel.app");
    scanFetchMock.mockResolvedValue({ status: 404, body: "The page could not be found\n\nNOT_FOUND\n404: NOT_FOUND" });
    expect(await site("api.example.com")).toEqual([]);
  });

  it("does NOT flag a live Ghost or Tumblr page whose copy quotes the fingerprint phrase", async () => {
    const copy = "<article>Why the thing you were looking for is no longer here, or never was — and Whatever you were looking for doesn't currently exist at this address</article>";
    cnameTo("blog.ghost.io");
    scanFetchMock.mockResolvedValue({ status: 200, body: copy });
    expect(await site("blog.example.com")).toEqual([]);
    cnameTo("x.tumblr.com");
    expect(await site("t.example.com")).toEqual([]);
  });

  it("does NOT flag a large live error-styled page even with an error status", async () => {
    cnameTo("x.ghost.io");
    scanFetchMock.mockResolvedValue({ status: 404, body: "The thing you were looking for is no longer here, or never was" + " x".repeat(15_000) });
    expect(await site("blog.example.com")).toEqual([]);
  });
});

describe("checkSubdomainTakeover — real unclaimed-resource pages are still detected", () => {
  const cases: Array<[string, string, number, string, string]> = [
    ["Vercel", "x.vercel.app", 404, "The deployment could not be found on Vercel.\n\nDEPLOYMENT_NOT_FOUND", "critical"],
    ["Ghost Pro", "x.ghost.io", 404, "<h1>Site unavailable</h1><p>The thing you were looking for is no longer here, or never was</p>", "high"],
    ["Tumblr", "x.tumblr.com", 404, "Whatever you were looking for doesn't currently exist at this address.", "medium"],
    ["Readme.io", "x.readme.io", 404, "<h1>Project doesnt exist... yet!</h1>", "high"],
    ["Readme.io", "x.readme.io", 404, "<p>The creators of this project are still working on making everything perfect!</p>", "high"],
    ["Ghost Pro", "x.ghost.io", 404, "<h1>Site unavailable.</h1><p>Failed to resolve DNS path for this host</p>", "high"],
    ["Heroku", "x.herokuapp.com", 404, "<title>No such app</title>", "critical"],
    ["GitHub Pages", "x.github.io", 404, "<p>There isn't a GitHub Pages site here.</p>", "critical"],
  ];
  it.each(cases)("%s", async (name, target, status, body, severity) => {
    vi.stubGlobal("fetch", vi.fn(async () => doh(target)));
    scanFetchMock.mockResolvedValue({ status, body });
    const findings = await checkSubdomainTakeover("https://gone.example.com");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toContain(name);
    expect(findings[0]!.severity).toBe(severity);
    expect(findings[0]!.confidence).toBeGreaterThanOrEqual(85);
  });

  it("Netlify and Fly.io bare 404s are reported only as unverified, low-confidence candidates", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => doh("x.netlify.app")));
    scanFetchMock.mockResolvedValue({ status: 404, body: "Not Found - Request ID: 01HABCDEF-XYZ" });
    let f = await checkSubdomainTakeover("https://gone.example.com");
    expect(f[0]!.name).toContain("Unverified");
    expect(f[0]!.severity).toBe("medium");
    expect(f[0]!.confidence).toBeLessThan(50);
    expect(f[0]!.description).toMatch(/verify/i);

    vi.stubGlobal("fetch", vi.fn(async () => doh("x.fly.dev")));
    scanFetchMock.mockResolvedValue({ status: 404, body: "404 Not Found" });
    f = await checkSubdomainTakeover("https://gone.example.com");
    expect(f[0]!.severity).toBe("medium");
  });
});
