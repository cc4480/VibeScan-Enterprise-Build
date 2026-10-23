import { describe, it, expect } from "vitest";
import { serve, SESSION, ep } from "./apiProbe.testkit";
import { runWithScanHttp } from "./http.js";
import { runApiProbes } from "./apiProbe.js";
import { isNotFoundBody } from "./apiProbeHelpers.js";
import { detectCatchAll, matchesCatchAll } from "./spaCatchAll.js";
import { runInjectionProbes } from "./injectionProbe.js";

// Hosts that answer 200 to anything. Found by pointing the scanner at a clean twin of the vuln fixture
// whose router answered every unrouted path with 200: each case below used to be reported.

const shell = (path: string) => `<!doctype html><html><head><title>Clean Co.</title></head><body><div id="root"></div>${path}</body></html>`;
const jsonNotFound = (path: string) => JSON.stringify({ error: "not found", path, status: 404 });

/** A host with real routes only for the signed-in invoice API; everything else gets `fallback`. */
function catchAllHost(fallback: (path: string) => { type: string; body: string }) {
  return serve((req, res) => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const signedIn = (req.headers.cookie ?? "").includes("sid=valid");
    if (path === "/api/invoices/1" && req.method === "DELETE") {
      res.writeHead(signedIn ? 204 : 401); res.end(); return;
    }
    const f = fallback(path);
    res.writeHead(200, { "content-type": f.type, "ratelimit-limit": "100" });
    res.end(f.body);
  });
}

describe.each([
  ["a JSON not-found sent with 200", (p: string) => ({ type: "application/json", body: jsonNotFound(p) })],
  ["the app shell for every path", (p: string) => ({ type: "text/html", body: shell(p) })],
])("API probes on a host that answers %s", (_label, fallback) => {
  it("reports none of: unprotected write, unauthenticated API, missing rate limit", async () => {
    const port = await catchAllHost(fallback);
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [
          ep({ url: `http://localhost:${port}/api/invoices/{id}` }),
          ep({ url: `http://localhost:${port}/api/me/password` }),
        ],
        credentials: SESSION,
      }),
    );
    expect(findings.map((f) => f.name)).toEqual([]);
  });
});

describe("isNotFoundBody", () => {
  it.each([
    ['{"error":"not found","path":"/x","status":404}'],
    ['{"statusCode":404,"message":"Route GET:/x not found"}'],
    ["<html><head><title>Page not found</title></head><body></body></html>"],
    ["Cannot PATCH /api/x"],
    ["404"],
  ])("recognises %s", (b) => expect(isNotFoundBody(b)).toBe(true));

  it.each([
    ['{"id":"1","owner":"alice","total":120}'],
    ['{"error":null,"data":{"id":1}}'],
    ['{"results":[{"name":"Not Found Cafe"}]}'],
    ["<html><head><title>Dashboard</title></head></html>"],
  ])("leaves %s alone", (b) => expect(isNotFoundBody(b)).toBe(false));
});

describe("catch-all fingerprint when the body echoes the requested path", () => {
  it("matches a probed path whose echo changes the body length", async () => {
    const port = await serve((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(jsonNotFound(path));
    });
    const origin = `http://localhost:${port}`;
    const baseline = await runWithScanHttp({ targetUrl: `${origin}/` }, () => detectCatchAll(origin));
    expect(baseline).not.toBeNull();
    // /xmlrpc.php is short, the nonce path is long: the raw lengths differ by far more than 3%.
    expect(matchesCatchAll(jsonNotFound("/xmlrpc.php"), baseline, `${origin}/xmlrpc.php`)).toBe(true);
    expect(matchesCatchAll(jsonNotFound("/.vscode/settings.json"), baseline, `${origin}/.vscode/settings.json`)).toBe(true);
  });

  it("still sees real content at a path as different from the catch-all", async () => {
    const baseline = { bodyLength: jsonNotFound("").length, title: "" };
    const real = '<?xml version="1.0"?><methodResponse><fault><value><int>-32601</int></value></fault></methodResponse>';
    expect(matchesCatchAll(real, baseline, "http://h/xmlrpc.php")).toBe(false);
  });
});

describe("reflected XSS evidence", () => {
  it("names the path that reflected, not the page the scan started on", async () => {
    // A real server: only /search reflects its query into the page.
    const port = await serve((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      const body = u.pathname === "/search" ? "<html><body>Results for: " + u.searchParams.get("q") + "</body></html>" : "<html><body>Home</body></html>";
      res.writeHead(200, { "content-type": "text/html" });
      res.end(body);
    });
    const origin = "http://127.0.0.1:" + port;
    const findings = await runWithScanHttp({ targetUrl: origin + "/" }, () => runInjectionProbes(origin + "/", '<a href="/search?q=test">Search</a>'));
    const xss = findings.find((f) => f.name === "Reflected Cross-Site Scripting (XSS)");
    expect(xss?.evidence).toContain("Endpoint: /search?q=");
  });
});
