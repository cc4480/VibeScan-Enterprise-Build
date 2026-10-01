/**
 * runScan end to end against local servers, for the cases where what the scan analyses is not the
 * app: a platform sign-in wall, a headless-only challenge, an error at the start page. The browser
 * is mocked so the render can be made to disagree with the plain request.
 */
import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";

const render = vi.hoisted(() => ({ next: null as null | { html: string; status: number; headers?: Record<string, string> } }));
vi.mock("./browser", () => ({
  isSpa: (html: string) => /<div id="root"><\/div>/.test(html),
  renderPage: async (url: string) =>
    render.next
      ? { html: render.next.html, status: render.next.status, headers: render.next.headers ?? {}, setCookies: [], finalUrl: url, observed: [] }
      : null,
  initBrowser: async () => {},
  closeBrowser: async () => {},
}));

import { runScan } from "./scanner";

const servers: http.Server[] = [];
afterAll(() => servers.forEach((s) => s.close()));

async function serve(handler: http.RequestListener): Promise<string> {
  const s = http.createServer(handler);
  servers.push(s);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(s.address() as AddressInfo).port}/`;
}

const SPA = `<!doctype html><html><head><title>App</title><script type="module" src="/assets/i.js"></script></head><body><div id="root"></div></body></html>`;

beforeEach(() => { render.next = null; });

describe("runScan when something other than the app answers", () => {
  it("withholds findings read from a Vercel Deployment Protection page, lists them, and does not grade", async () => {
    const url = await serve((_req, res) => {
      res.writeHead(401, { "content-type": "text/html", server: "Vercel", "set-cookie": "_vercel_sso_nonce=abc; Path=/" });
      res.end(`<!doctype html><html><head><title>Authentication Required</title></head><body><script>location.href="https://vercel.com/sso-api?url="+encodeURIComponent(location.href)</script></body></html>`);
    });
    const r = await runScan(url, "deep", false);
    expect(r.intercepted).toBe(true);
    expect(r.interception).toMatchObject({ kind: "sign-in wall", vendor: "Vercel Deployment Protection" });
    const names = r.vulnerabilities.map((v) => v.name);
    expect(names).toContain("Scan reached a sign-in page, not the app");
    expect(names).not.toContain("Missing Content-Security-Policy (CSP)");
    expect(r.withheld?.map((w) => w.name)).toContain("Missing Content-Security-Policy (CSP)");
    expect(r.withheld?.every((w) => /sign-in page/.test(w.reason))).toBe(true);
    // Nothing that read the sign-in page may claim to have tested the app.
    const ranOnPage = (r.tests ?? []).filter(
      (t) => t.status === "ran" && !["DNS and email authentication", "mail transport security (STARTTLS, MX certificate)", "subdomain takeover", "GitHub source code secrets"].includes(t.name),
    );
    expect(ranOnPage.map((t) => t.name)).toEqual([]);
    expect(r.tests?.find((t) => t.name === "security.txt")).toMatchObject({ status: "skipped", reason: expect.stringMatching(/not tested on the app: a sign-in page answered/) });
  }, 60_000);

  it("sets aside a render that met a challenge served with HTTP 200 only to the browser", async () => {
    const url = await serve((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end(SPA); });
    render.next = { status: 200, html: `<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={}</script></body></html>` };
    const r = await runScan(url, "deep", false);
    expect(r.renderedWithBrowser).toBe(false);
    expect(r.intercepted).toBe(false);
    const note = r.vulnerabilities.find((v) => v.name === "Browser Rendering Was Not Used");
    expect(note?.evidence).toMatch(/bot-protection challenge/);
  }, 60_000);

  it("sets aside a render answered with an error the plain request did not get", async () => {
    const url = await serve((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end(SPA); });
    render.next = { status: 403, html: "<html><body>Forbidden</body></html>" };
    const r = await runScan(url, "deep", false);
    expect(r.renderedWithBrowser).toBe(false);
    expect(r.vulnerabilities.find((v) => v.name === "Browser Rendering Was Not Used")?.evidence).toMatch(/HTTP 403 where the plain request got HTTP 200/);
  }, 60_000);

  it("uses a render that agrees with the plain request", async () => {
    const url = await serve((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end(SPA); });
    render.next = { status: 200, html: `<html><head><title>App</title></head><body><div id="root"><h1>Hello</h1></div></body></html>` };
    const r = await runScan(url, "deep", false);
    expect(r.renderedWithBrowser).toBe(true);
    expect(r.vulnerabilities.some((v) => v.name === "Browser Rendering Was Not Used")).toBe(false);
  }, 60_000);

  it("says when the start page was an error response, and keeps the findings", async () => {
    const url = await serve((_req, res) => { res.writeHead(502, { "content-type": "text/html" }); res.end("<html><body><h1>Bad gateway</h1><p>The upstream did not answer in time.</p></body></html>".repeat(30)); });
    const r = await runScan(url, "deep", false);
    expect(r.intercepted).toBe(false);
    expect(r.vulnerabilities.find((v) => v.name === "Scan started from an error response")?.evidence).toMatch(/HTTP 502/);
  }, 60_000);

  it("records checks that had nothing to test as not tested, with the reason", async () => {
    const url = await serve((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end("<html><head><title>Plain</title></head><body><h1>Plain</h1></body></html>"); });
    const r = await runScan(url, "deep", false);
    const next = r.tests?.find((t) => t.name === "Next.js __NEXT_DATA__ secrets");
    expect(next).toMatchObject({ status: "skipped" });
    expect(next?.reason).toMatch(/not a Next\.js page/);
    expect(r.tests?.find((t) => t.name === "JWT analysis")?.status).toBe("skipped");
  }, 60_000);
});
