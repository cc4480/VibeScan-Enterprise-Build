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
    expect(findings[0]!.severity).toBe("critical");
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
