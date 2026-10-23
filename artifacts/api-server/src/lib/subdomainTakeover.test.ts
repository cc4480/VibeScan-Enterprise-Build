import { describe, it, expect, beforeEach, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { useDohStub } from "./dohStub.testkit";
import { checkSubdomainTakeover } from "./subdomainTakeover.js";

// The CNAME comes from a real DNS-over-HTTPS server on loopback (lib/dohStub.testkit.ts). The hostname's own web server
// is a real HTTP server too: TAKEOVER_PROBE_ORIGIN sends the check's request to it, naming the hostname in X-Probe-Host,
// so what the server answers is decided here and which hostname it was asked about is recorded.
const doh = await useDohStub();

const site = { status: 200, body: "", hosts: [] as string[] };
const server = http.createServer((req, res) => {
  site.hosts.push(String(req.headers["x-probe-host"]));
  res.writeHead(site.status, { "content-type": "text/html" }).end(site.body);
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
process.env["TAKEOVER_PROBE_ORIGIN"] = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
afterAll(() => new Promise<void>((r) => {
  delete process.env["TAKEOVER_PROBE_ORIGIN"];
  server.closeAllConnections();
  server.close(() => r());
}));

const CNAME = 5;
/** The hostname is a CNAME to `target`, and its web server answers with this. */
function serve(host: string, target: string, status: number, body: string) {
  doh.set(host, "CNAME", [{ data: target, type: CNAME }]);
  site.status = status;
  site.body = body;
}

beforeEach(() => {
  site.status = 200;
  site.body = "";
  site.hosts.length = 0;
});

describe("checkSubdomainTakeover — Host-routing false positive", () => {
  it("does NOT flag a live Fastly-fronted site whose hostname serves real content", async () => {
    // The exact www.reddit.com false positive: the CNAME points to
    // *.fastly.net, but the real hostname serves the real site. The buggy
    // version fetched the raw CNAME target, which returns Fastly's
    // "unknown domain" error and looked like a takeover.
    serve("www.reddit.com", "reddit.map.fastly.net", 200, "<!doctype html><html><body>Welcome to Reddit</body></html>");

    const findings = await checkSubdomainTakeover("https://www.reddit.com");
    expect(findings).toEqual([]);
  });

  it("STILL flags a genuinely dangling CNAME whose hostname returns the provider's unclaimed error", async () => {
    serve(
      "abandoned.example.com",
      "reddit.map.fastly.net",
      404,
      "Fastly error: unknown domain: abandoned.example.com. Please check that this domain has been added to a service.",
    );

    const findings = await checkSubdomainTakeover("https://abandoned.example.com");
    expect(findings.length).toBe(1);
    expect(findings[0]!.name).toMatch(/Subdomain Takeover/);
    // Fastly is "Not vulnerable" in can-i-take-over-xyz: reported only as an unverified candidate.
    expect(findings[0]!.name).toContain("Unverified");
    expect(findings[0]!.severity).toBe("medium");
  });

  it("asks for the hostname, never the raw CNAME target", async () => {
    serve("www.reddit.com", "reddit.map.fastly.net", 200, "real site");
    await checkSubdomainTakeover("https://www.reddit.com");
    expect(site.hosts.length).toBeGreaterThan(0);
    for (const host of site.hosts) {
      expect(host).toBe("www.reddit.com");
    }
  });
});

describe("checkSubdomainTakeover — live hosts that merely CNAME to a provider", () => {
  const site_ = (host: string) => checkSubdomainTakeover(`https://${host}`);

  it("does NOT flag a live minified Netlify page that mentions netlify and 404 on one line", async () => {
    serve("www.example.com", "app.netlify.app", 200, '<html><script>/* built on netlify */var e="404";</script><body>Welcome</body></html>');
    expect(await site_("www.example.com")).toEqual([]);
  });

  it("does NOT flag a live Fly.io API whose root answers 404 Not Found with a JSON body", async () => {
    serve("api.example.com", "api.fly.dev", 200, "404 Not Found");
    expect(await site_("api.example.com")).toEqual([]);
  });

  it("does NOT flag a Vercel API-only project whose route answers 404: NOT_FOUND", async () => {
    serve("api.example.com", "api.vercel.app", 404, "The page could not be found\n\nNOT_FOUND\n404: NOT_FOUND");
    expect(await site_("api.example.com")).toEqual([]);
  });

  it("does NOT flag a live Ghost or Tumblr page whose copy quotes the fingerprint phrase", async () => {
    const copy = "<article>Why the thing you were looking for is no longer here, or never was — and Whatever you were looking for doesn't currently exist at this address</article>";
    serve("blog.example.com", "blog.ghost.io", 200, copy);
    expect(await site_("blog.example.com")).toEqual([]);
    serve("t.example.com", "x.tumblr.com", 200, copy);
    expect(await site_("t.example.com")).toEqual([]);
  });

  it("does NOT flag a large live error-styled page even with an error status", async () => {
    serve("blog.example.com", "x.ghost.io", 404, "The thing you were looking for is no longer here, or never was" + " x".repeat(15_000));
    expect(await site_("blog.example.com")).toEqual([]);
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
    serve("gone.example.com", target, status, body);
    const findings = await checkSubdomainTakeover("https://gone.example.com");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toContain(name);
    expect(findings[0]!.severity).toBe(severity);
    expect(findings[0]!.confidence).toBeGreaterThanOrEqual(85);
  });

  it("Netlify and Fly.io bare 404s are reported only as unverified, low-confidence candidates", async () => {
    serve("gone.example.com", "x.netlify.app", 404, "Not Found - Request ID: 01HABCDEF-XYZ");
    let f = await checkSubdomainTakeover("https://gone.example.com");
    expect(f[0]!.name).toContain("Unverified");
    expect(f[0]!.severity).toBe("medium");
    expect(f[0]!.confidence).toBeLessThan(50);
    expect(f[0]!.description).toMatch(/verify/i);

    serve("gone.example.com", "x.fly.dev", 404, "404 Not Found");
    f = await checkSubdomainTakeover("https://gone.example.com");
    expect(f[0]!.severity).toBe("medium");
  });
});
