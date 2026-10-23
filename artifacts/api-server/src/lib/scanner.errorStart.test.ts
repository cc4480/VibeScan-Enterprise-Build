/**
 * What a scan makes of a start page that answers an error.
 *
 * www.elastic.co (Fastly) answered the scanner's request with HTTP 406 and the body "406 Not Acceptable".
 * The scan read that response as the site: a HIGH "Missing Content-Security-Policy", a MEDIUM missing
 * X-Frame-Options, missing cache headers, no structured data, no Open Graph tags. All five claims are false
 * of the real page (2026-10-10, repeated on the live commit 2026-10-11).
 *
 *  - A bare refusal (almost no body: 400, 403, 406, 429, 451, 503) is an interception: findings withheld, no grade.
 *  - An error page with real content (404, 500, 502...) is kept, but what was read from it is information only.
 */
import { describe, it, expect, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { useHstsPreloadStub } from "./hstsPreloadStub.testkit";

// The preload lookup is a real server on loopback that lists nothing; the start pages here are not single-page apps,
// so the real headless browser is never needed.
await useHstsPreloadStub();

import { runScan, gradeForResult, computeRiskScore } from "./scanner";
import { detectChallengePage } from "./challengePage";
import { capFindingsReadFromErrorPage } from "./scannerCoverage";
import type { ScanVulnerability } from "./scannerTypes";

const servers: http.Server[] = [];
afterAll(() => servers.forEach((s) => s.close()));
async function serve(handler: http.RequestListener): Promise<string> {
  const s = http.createServer(handler);
  servers.push(s);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(s.address() as AddressInfo).port}/`;
}

const names = (r: { vulnerabilities: Array<{ name: string }> }) => r.vulnerabilities.map((v) => v.name);
const find = (r: { vulnerabilities: ScanVulnerability[] }, re: RegExp) => r.vulnerabilities.find((v) => re.test(v.name));

/** A page with real content: more than the 2,000 non-space characters that make a body "bare". */
const REAL_PAGE = (title: string) => `<html><head><title>${title}</title></head><body>${"<p>The upstream did not answer in time, please try again later.</p>".repeat(60)}</body></html>`;

describe("detectChallengePage: a bare refusal", () => {
  it.each([400, 403, 406, 429, 451, 503])("HTTP %i with a tiny body is a refusal", (status) => {
    const v = detectChallengePage(status, "406 Not Acceptable", {});
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBeNull();
    expect(v.signal).toMatch(new RegExp(`HTTP ${status} with a 18-byte body`));
  });

  it.each([401, 404, 410, 500, 502, 504])("HTTP %i with a tiny body is not (the page or the server is missing; nothing was refused)", (status) => {
    expect(detectChallengePage(status, "Not Found", {}).isChallenge).toBe(false);
  });

  it("a 406 with a real page around it is left alone", () => {
    expect(detectChallengePage(406, REAL_PAGE("Not acceptable"), {}).isChallenge).toBe(false);
  });
});

describe("runScan: the elastic.co case", () => {
  it("withholds what a 406 page says and does not grade it", async () => {
    const url = await serve((_req, res) => { res.writeHead(406, { "content-type": "text/plain; charset=utf-8" }); res.end("406 Not Acceptable"); });
    const r = await runScan(url, "deep", false);
    expect(r.statusCode).toBe(406);
    expect(r.intercepted).toBe(true);
    expect(gradeForResult(computeRiskScore(r.vulnerabilities), r.intercepted)).toBe("N/A");
    // None of the five claims that were false of elastic.co is made.
    expect(find(r, /Missing Content-Security-Policy/)).toBeUndefined();
    expect(find(r, /Clickjacking/)).toBeUndefined();
    expect(find(r, /No Structured Data/)).toBeUndefined();
    expect(find(r, /Open Graph/)).toBeUndefined();
    expect(find(r, /Cache-Control/)).toBeUndefined();
    // They are listed as withheld, with the reason, and the scan says what happened.
    expect(r.withheld?.some((w) => /Content-Security-Policy/.test(w.name))).toBe(true);
    expect(find(r, /intercepted by a bot-protection challenge/)?.evidence).toMatch(/HTTP 406/);
  }, 60_000);

  it("clean twin: the same site answering 200 is read as before, and graded", async () => {
    const url = await serve((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end(REAL_PAGE("Home")); });
    const r = await runScan(url, "deep", false);
    expect(r.intercepted).toBe(false);
    expect(find(r, /Missing Content-Security-Policy/)?.severity).toBe("high");
    expect(find(r, /Scan started from an error response/)).toBeUndefined();
  }, 60_000);
});

describe("runScan: an error page with real content", () => {
  it("reports what was read from it as information, keeps the note, and says so", async () => {
    const url = await serve((_req, res) => { res.writeHead(502, { "content-type": "text/html" }); res.end(REAL_PAGE("Bad gateway")); });
    const r = await runScan(url, "deep", false);
    expect(r.intercepted).toBe(false);
    const note = find(r, /Scan started from an error response/);
    expect(note?.evidence).toMatch(/HTTP 502/);
    expect(note?.description).toMatch(/information only/);
    const csp = find(r, /Missing Content-Security-Policy/);
    expect(csp?.severity).toBe("info");
    expect(csp?.cvssScore).toBe(0);
    expect(csp?.confidence).toBeLessThanOrEqual(40);
    expect(csp?.description).toMatch(/HTTP 502/);
    expect(csp?.description).toMatch(/high before the cap/);
    // Nothing read from the error page counts against the site.
    const fromPage = r.vulnerabilities.filter((v) => /Content-Security-Policy|Clickjacking|X-Content-Type|Referrer-Policy|Permissions-Policy/.test(v.name));
    expect(fromPage.length).toBeGreaterThan(0);
    expect(fromPage.every((v) => v.severity === "info")).toBe(true);
  }, 60_000);

  it("a 404 start page is treated the same way", async () => {
    const url = await serve((_req, res) => { res.writeHead(404, { "content-type": "text/html" }); res.end(REAL_PAGE("Not found")); });
    const r = await runScan(url, "deep", false);
    expect(find(r, /Scan started from an error response/)?.evidence).toMatch(/HTTP 404/);
    expect(find(r, /Missing Content-Security-Policy/)?.severity).toBe("info");
  }, 60_000);

  it("does not touch what a probe found by asking for its own path", async () => {
    // The root is an error page, but /.env answers with real secrets: that finding is true whatever the root said.
    const url = await serve((req, res) => {
      if (req.url === "/.env") { res.writeHead(200, { "content-type": "text/plain" }); res.end("# prod\nDATABASE_URL=postgres://u:p@db/x\nJWT_SECRET=Zq8vK2mT9xW4pL7c\n"); return; }
      res.writeHead(500, { "content-type": "text/html" }); res.end(REAL_PAGE("Server error"));
    });
    const r = await runScan(url, "deep", false);
    expect(find(r, /Environment File Exposed \(\.env\)/)?.severity).toBe("critical");
    expect(find(r, /Missing Content-Security-Policy/)?.severity).toBe("info");
  }, 60_000);
});

describe("capFindingsReadFromErrorPage", () => {
  const f = (name: string, severity: ScanVulnerability["severity"]) =>
    ({ id: name, name, severity, category: "x", description: "d", evidence: "e", solution: "s", cweId: null, cvssScore: 7, confidence: 90 }) as unknown as ScanVulnerability;

  it("caps everything above information and leaves information alone", () => {
    const out = capFindingsReadFromErrorPage([f("A", "high"), f("B", "medium"), f("C", "info")], 503);
    expect(out.map((v) => v.severity)).toEqual(["info", "info", "info"]);
    expect(out[0]!.cvssScore).toBe(0);
    expect(out[2]!.cvssScore).toBe(7);
  });

  it("keeps the plaintext-HTTP finding at its severity: that is about the address, not the response", () => {
    const out = capFindingsReadFromErrorPage([f("No HTTPS / Plaintext HTTP", "critical")], 404);
    expect(out[0]!.severity).toBe("critical");
  });
});
