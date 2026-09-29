import { describe, it, expect } from "vitest";

// ─── The root's headers are only a baseline when the root is the site ────────
//
// www.reddit.com answered GET / with a proof-of-work interstitial that carries its own CSP
// ("default-src 'none'; ..."). The crawler took it as "the root has a CSP" and reported
// "Content-Security-Policy Missing on 6 Internal Routes" for every inner page that lacked it
// (verified 2026-09-29). And an inner route that is itself a WAF page carries the WAF's headers,
// not the application's, so it cannot be a gap in the application's either.

import http from "node:http";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { afterEach } from "vitest";
import { crawlAndCheck } from "./crawler.js";

const fixture = (name: string): string => readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), "utf8");
const REDDIT_CHALLENGE = fixture("reddit-challenge.html");
const REDDIT_CSP = "default-src 'none'; script-src 'nonce-b53c6e07'; style-src 'unsafe-inline'; img-src https://www.redditstatic.com; form-action 'self';";
const CF_INTERSTITIAL = `<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script></body></html>`;

const crawlServers: http.Server[] = [];
async function serveRoutes(routes: Record<string, { headers?: Record<string, string>; body: string; status?: number }>): Promise<string> {
  const srv = http.createServer((req, res) => {
    const route = routes[(req.url ?? "/").split("?")[0]!];
    if (!route) { res.writeHead(404, { "content-type": "text/plain" }).end("not found"); return; }
    res.writeHead(route.status ?? 200, { "content-type": "text/html", ...(route.headers ?? {}) });
    res.end(route.body);
  });
  crawlServers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}
afterEach(async () => {
  await Promise.all(crawlServers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const page = (title: string) => `<html><head><title>${title}</title></head><body><h1>${title}</h1>${"<p>content</p>".repeat(40)}</body></html>`;

describe("crawlAndCheck header-gap baseline", () => {
  it("reports no CSP gap when the root's CSP came from a challenge interstitial (Reddit)", async () => {
    const origin = await serveRoutes({
      "/": { body: REDDIT_CHALLENGE, headers: { "content-security-policy": REDDIT_CSP, server: "snooserv" } },
      // Ordinary pages, served without a CSP, the way the verifier saw /live.
      "/ready": { body: page("ready") },
      "/auth": { body: page("auth") },
      "/signin": { body: page("signin") },
    });
    const result = await crawlAndCheck(
      `${origin}/`, REDDIT_CHALLENGE,
      { "content-security-policy": REDDIT_CSP, server: "snooserv", "content-type": "text/html" },
      [], 5,
    );
    const gaps = result.vulnerabilities.filter((v) => /Missing on \d+ Internal Route/.test(v.name));
    expect(gaps.map((v) => v.name)).toEqual([]);
  });

  it("still reports the gap when the root is a real page with a CSP", async () => {
    // The same three inner routes, but the baseline is genuine: this is the finding the check exists for.
    const rootHtml = page("Acme");
    const origin = await serveRoutes({
      "/": { body: rootHtml, headers: { "content-security-policy": "default-src 'self'" } },
      "/ready": { body: page("ready") },
      "/auth": { body: page("auth") },
    });
    const result = await crawlAndCheck(
      `${origin}/`, rootHtml,
      { "content-security-policy": "default-src 'self'", "content-type": "text/html" },
      [], 5,
    );
    expect(result.vulnerabilities.some((v) => /Content-Security-Policy Missing on 2 Internal Routes/.test(v.name))).toBe(true);
  });

  it("does not count an inner route that is itself a challenge page as a gap", async () => {
    const rootHtml = page("Acme");
    const origin = await serveRoutes({
      "/": { body: rootHtml, headers: { "content-security-policy": "default-src 'self'" } },
      // Cloudflare's own interstitial, served as 200 on two routes: no CSP because it is not the app's.
      "/auth": { body: CF_INTERSTITIAL },
      "/signin": { body: CF_INTERSTITIAL },
    });
    const result = await crawlAndCheck(
      `${origin}/`, rootHtml,
      { "content-security-policy": "default-src 'self'", "content-type": "text/html" },
      [], 5,
    );
    expect(result.vulnerabilities.filter((v) => /Missing on \d+ Internal Route/.test(v.name))).toEqual([]);
    expect(result.pagesVisited).not.toContain(`${origin}/auth`);
  });

  it("keeps a real inner gap when only some routes are challenge pages", async () => {
    const rootHtml = page("Acme");
    const origin = await serveRoutes({
      "/": { body: rootHtml, headers: { "content-security-policy": "default-src 'self'" } },
      "/auth": { body: CF_INTERSTITIAL },
      "/ready": { body: page("ready") },
    });
    const result = await crawlAndCheck(
      `${origin}/`, rootHtml,
      { "content-security-policy": "default-src 'self'", "content-type": "text/html" },
      [], 5,
    );
    const csp = result.vulnerabilities.find((v) => /Content-Security-Policy Missing on/.test(v.name));
    expect(csp?.name).toBe("Content-Security-Policy Missing on 1 Internal Route");
    expect(csp?.evidence).toContain("/ready");
    expect(csp?.evidence).not.toContain("/auth");
  });
});
