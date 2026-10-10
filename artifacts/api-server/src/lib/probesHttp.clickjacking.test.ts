import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { checkClickjacking, xfoBlocksFraming } from "./probesHttp.js";
import { cspRestrictsFraming } from "./headerAnalysis.js";

const servers: http.Server[] = [];
async function serve(headers: Record<string, string | string[]>): Promise<number> {
  const srv = http.createServer((_req, res) => {
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.writeHead(200, { "Content-Type": "text/html" }).end("<!doctype html><title>ok</title>");
  });
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const clickjacking = async (headers: Record<string, string | string[]>) => {
  const port = await serve(headers);
  return runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () => checkClickjacking(`http://localhost:${port}/`));
};

describe("checkClickjacking — the header is judged the way a browser reads it", () => {
  it.each([
    ["DENY", { "X-Frame-Options": "DENY" }],
    // App and proxy both add it; fetch joins the two into "SAMEORIGIN, SAMEORIGIN".
    ["the same value sent twice", { "X-Frame-Options": ["SAMEORIGIN", "SAMEORIGIN"] }],
    // Browsers that support CSP ignore X-Frame-Options when frame-ancestors is set.
    ["legacy ALLOW-FROM next to CSP frame-ancestors", {
      "X-Frame-Options": "ALLOW-FROM https://partner.example",
      "Content-Security-Policy": "frame-ancestors 'self' https://partner.example",
    }],
  ])("does not flag %s", async (_n, headers) => {
    expect(await clickjacking(headers)).toEqual([]);
  });

  it.each([
    ["ALLOW-FROM alone, which no current browser supports", { "X-Frame-Options": "ALLOW-FROM https://partner.example" }],
    ["ALLOWALL", { "X-Frame-Options": "ALLOWALL" }],
    ["ALLOWALL next to a frame-ancestors that allows every origin", {
      "X-Frame-Options": "ALLOWALL",
      "Content-Security-Policy": "frame-ancestors *",
    }],
  ])("flags %s", async (_n, headers) => {
    const found = await clickjacking(headers);
    expect(found).toHaveLength(1);
    expect(found[0]!.name).toBe("X-Frame-Options Header Misconfigured");
  });
});

describe("cspRestrictsFraming", () => {
  it("counts only a frame-ancestors that limits who may embed the page", () => {
    expect(cspRestrictsFraming("frame-ancestors 'none'")).toBe(true);
    expect(cspRestrictsFraming("default-src 'self'; frame-ancestors 'self' https://a.example")).toBe(true);
    expect(cspRestrictsFraming("FRAME-ANCESTORS 'self'")).toBe(true);
    expect(cspRestrictsFraming("frame-ancestors *")).toBe(false);
    expect(cspRestrictsFraming("frame-ancestors https:")).toBe(false);
    expect(cspRestrictsFraming("frame-ancestors 'self' *")).toBe(false);
    expect(cspRestrictsFraming("default-src 'self'")).toBe(false);
    expect(cspRestrictsFraming("")).toBe(false);
    expect(cspRestrictsFraming(undefined)).toBe(false);
    // Two policies are enforced together, so the restrictive one wins.
    expect(cspRestrictsFraming("frame-ancestors *, frame-ancestors 'none'")).toBe(true);
  });
});

describe("xfoBlocksFraming", () => {
  it("follows the HTML spec's set processing", () => {
    expect(xfoBlocksFraming("sameorigin")).toBe(true);
    expect(xfoBlocksFraming(" DENY ")).toBe(true);
    expect(xfoBlocksFraming("SAMEORIGIN, SAMEORIGIN")).toBe(true);
    // Different values that include a known one: framing is blocked outright.
    expect(xfoBlocksFraming("DENY, SAMEORIGIN")).toBe(true);
    expect(xfoBlocksFraming("SAMEORIGIN, ALLOW-FROM https://a.example")).toBe(true);
    // A single unsupported or unknown value is ignored by the browser.
    expect(xfoBlocksFraming("ALLOW-FROM https://a.example")).toBe(false);
    expect(xfoBlocksFraming("ALLOWALL")).toBe(false);
    expect(xfoBlocksFraming("nonsense")).toBe(false);
    expect(xfoBlocksFraming("")).toBe(false);
  });
});
