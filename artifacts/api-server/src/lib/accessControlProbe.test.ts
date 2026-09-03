import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import {
  runAccessControlProbes,
  namesARecord,
  contentSimilarity,
} from "./accessControlProbe.js";

const servers: http.Server[] = [];

async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<number> {
  const srv = http.createServer(handler);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

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

describe("namesARecord", () => {
  it.each([
    "https://a.example/orders/1042",
    "https://a.example/users/550e8400-e29b-41d4-a716-446655440000",
    "https://a.example/invoice?id=88",
    "https://a.example/doc?record_id=abc123def",
  ])("recognises %s", (url) => {
    expect(namesARecord(url)).toBe(true);
  });

  it.each([
    "https://a.example/dashboard",
    "https://a.example/settings/profile",
    "https://a.example/about",
    "https://a.example/search?q=hello",
  ])("ignores %s, which names no particular record", (url) => {
    expect(namesARecord(url)).toBe(false);
  });
});

describe("contentSimilarity", () => {
  it("treats a page as the same despite a rotating CSRF token", () => {
    const a = record("Ada", "<input name='csrf' value='a1b2c3d4e5f60718'>");
    const b = record("Ada", "<input name='csrf' value='99887766554433aa'>");
    expect(contentSimilarity(a, b)).toBeGreaterThan(0.9);
  });

  it("separates two different customers' records", () => {
    expect(contentSimilarity(record("Ada"), record("Grace"))).toBeLessThan(1);
  });

  it("scores unrelated pages low", () => {
    expect(contentSimilarity(record("Ada"), loginPage)).toBeLessThan(0.3);
  });
});

describe("runAccessControlProbes", () => {
  async function probe(port: number, urls: string[]) {
    return runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runAccessControlProbes({ urls, primary: OWNER, secondary: OTHER }),
    );
  }

  it("reports IDOR when a second account is served the first account's record", async () => {
    const port = await serve((req, res) => {
      const w = who(req);
      if (w === "anon") {
        res.writeHead(401, { "content-type": "text/html" });
        res.end(loginPage);
        return;
      }
      // The bug: any signed-in user gets the owner's invoice.
      res.writeHead(200, { "content-type": "text/html" });
      res.end(record("Ada"));
    });

    const findings = await probe(port, [`http://localhost:${port}/invoices/1042`]);

    expect(findings).toHaveLength(1);
    expect(findings[0].name).toMatch(/IDOR/);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].evidence).toContain("/invoices/1042");
  });

  it("stays quiet when each account sees its own record", async () => {
    const port = await serve((req, res) => {
      const w = who(req);
      if (w === "anon") {
        res.writeHead(401);
        res.end(loginPage);
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end(record(w === "owner" ? "Ada" : "Grace", `<p>Distinct ${w} content ${w} ${w}</p>`));
    });

    expect(await probe(port, [`http://localhost:${port}/invoices/1042`])).toEqual([]);
  });

  it("stays quiet when the second account is refused", async () => {
    const port = await serve((req, res) => {
      if (who(req) === "owner") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(record("Ada"));
        return;
      }
      res.writeHead(403);
      res.end("Forbidden");
    });

    expect(await probe(port, [`http://localhost:${port}/invoices/1042`])).toEqual([]);
  });

  it("reports unauthenticated exposure rather than IDOR when everyone can read it", async () => {
    // Same bytes to everyone: the finding is "no session required", and calling
    // it IDOR would misdescribe it.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(record("Ada"));
    });

    const findings = await probe(port, [`http://localhost:${port}/invoices/1042`]);

    expect(findings).toHaveLength(1);
    expect(findings[0].name).toMatch(/Without Signing In/i);
  });

  it("ignores URLs that name no record", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(record("Ada"));
    });

    // A public marketing page returns the same bytes to everyone, which is
    // exactly why reachability alone cannot be the signal.
    expect(await probe(port, [`http://localhost:${port}/pricing`])).toEqual([]);
  });

  it("never requests a destructive URL, even to test authorisation", async () => {
    const requested: string[] = [];
    const port = await serve((req, res) => {
      requested.push(req.url ?? "");
      res.writeHead(200, { "content-type": "text/html" });
      res.end(record("Ada"));
    });

    await probe(port, [`http://localhost:${port}/invoices/1042/delete`]);
    expect(requested).toEqual([]);
  });

  it("skips a record too thin to compare", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body>ok</body></html>");
    });

    expect(await probe(port, [`http://localhost:${port}/items/7`])).toEqual([]);
  });
});
