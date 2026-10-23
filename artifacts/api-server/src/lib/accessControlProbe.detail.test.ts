import { describe, it, expect, afterEach } from "vitest";
import type http from "node:http";
import { runWithScanHttp } from "./http.js";
import { runAccessControlProbes } from "./accessControlProbe.js";
import { serve, closeServers } from "./testkit";

afterEach(closeServers);

const OWNER = { cookie: "sid=owner" };
const OTHER = { cookie: "sid=other" };

function who(req: http.IncomingMessage): "owner" | "other" | "anon" {
  const c = req.headers.cookie ?? "";
  if (c.includes("sid=owner")) return "owner";
  if (c.includes("sid=other")) return "other";
  return "anon";
}

const loginPage = "<h1>Please log in</h1><form><input type='password' name='p'></form>";

/** Enough distinct words that the similarity comparison has something to work on. */
function record(owner: string, extra = "") {
  return `<html><body><h1>Invoice 1042</h1>
    <p>Customer ${owner} of Acme Industries, billing address 14 Rowan Street Bristol</p>
    <p>Line items: consulting retainer, hosting, support hours, travel expenses</p>
    <p>Totals: subtotal 4200, tax 840, due 5040, payable within thirty days</p>
    ${extra}</body></html>`;
}

// ─── How much was actually compared, and who the second account is ───────────

import { runAccessControlProbesDetailed, accessControlCandidates } from "./accessControlProbe.js";

describe("accessControlCandidates", () => {
  it("keeps record-shaped, non-destructive URLs, once each", () => {
    expect(
      accessControlCandidates([
        "https://a.example/",
        "https://a.example/orders/5",
        "https://a.example/orders/5",
        "https://a.example/orders/5/delete",
        "https://a.example/settings",
      ]),
    ).toEqual(["https://a.example/orders/5"]);
  });

  it("is empty when the crawl reached only pages, no records", () => {
    expect(accessControlCandidates(["https://a.example/dashboard", "https://a.example/settings"])).toEqual([]);
  });
});

describe("runAccessControlProbesDetailed", () => {
  const probeDetailed = (port: number, urls: string[], extra: Record<string, unknown> = {}) =>
    runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runAccessControlProbesDetailed({ urls, primary: OWNER, secondary: OTHER, ...extra }),
    );

  it("says nothing was compared when no URL names a record", async () => {
    const port = await serve((_req, res) => { res.writeHead(200).end(record("Ada")); });
    const r = await probeDetailed(port, [`http://localhost:${port}/dashboard`]);
    expect(r).toEqual({ findings: [], compared: 0 });
  });

  it("says nothing was compared when the owner's own request is refused", async () => {
    const port = await serve((_req, res) => { res.writeHead(403).end("no"); });
    expect((await probeDetailed(port, [`http://localhost:${port}/orders/5`])).compared).toBe(0);
  });

  it("says nothing was compared when the second account's request failed outright", async () => {
    // Owner gets a page; the second identity's request hangs up. No comparison was made, and a
    // result of "0 findings" must not read as "checked and clear".
    const port = await serve((req, res) => {
      if (who(req) === "other") { req.socket.destroy(); return; }
      res.writeHead(who(req) === "owner" ? 200 : 401, { "content-type": "text/html" }).end(record("Ada"));
    });
    const r = await probeDetailed(port, [`http://localhost:${port}/orders/5`]);
    expect(r.findings).toEqual([]);
    expect(r.compared).toBe(0);
  });

  it("counts a record that was compared, whatever the answer", async () => {
    const port = await serve((req, res) => {
      const w = who(req);
      if (w === "anon") { res.writeHead(401).end(loginPage); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(record(w === "owner" ? "Ada" : "Grace", `<p>${w} ${w} ${w}</p>`));
    });
    const r = await probeDetailed(port, [`http://localhost:${port}/orders/5`]);
    expect(r.findings).toEqual([]);
    expect(r.compared).toBeGreaterThanOrEqual(1);
  });

  it("marks the finding when the second account was created by the scan itself, and lowers its confidence", async () => {
    // A signup that drops every new user into one shared workspace makes identical content
    // expected. An account the user chose as 'owns different data' is a statement; one the scan
    // made for itself is not, and the report has to say so.
    const port = await serve((req, res) => {
      if (who(req) === "anon") { res.writeHead(401).end(loginPage); return; }
      if (!/\/invoices\/10\d\d$/.test(req.url ?? "")) { res.writeHead(404).end("Not found"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(record("Ada"));
    });
    const own = await probeDetailed(port, [`http://localhost:${port}/invoices/1042`]);
    const auto = await probeDetailed(port, [`http://localhost:${port}/invoices/1042`], { secondaryAutoCreated: true });
    const pick = (f: typeof own.findings) => f.find((x) => /Object-Level/.test(x.name))!;
    expect(pick(auto.findings).confidence).toBeLessThan(pick(own.findings).confidence ?? 100);
    expect(pick(auto.findings).evidence).toMatch(/created automatically/i);
    expect(pick(own.findings).evidence).not.toMatch(/created automatically/i);
    expect(pick(auto.findings).evidence).toMatch(/shared workspace|same organisation|tenant/i);
  });

  it("returns exactly what runAccessControlProbes returns", async () => {
    const port = await serve((req, res) => {
      if (who(req) === "anon") { res.writeHead(401).end(loginPage); return; }
      if (!/\/invoices\/10\d\d$/.test(req.url ?? "")) { res.writeHead(404).end("Not found"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(record("Ada"));
    });
    const urls = [`http://localhost:${port}/invoices/1042`];
    const a = await probeDetailed(port, urls);
    const b = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runAccessControlProbes({ urls, primary: OWNER, secondary: OTHER }),
    );
    expect(a.findings.map((f) => f.name)).toEqual(b.map((f) => f.name));
  });
});
