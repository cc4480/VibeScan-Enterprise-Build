import { describe, it, expect, afterEach } from "vitest";
import type http from "node:http";
import { runWithScanHttp } from "./http.js";
import { runAccessControlProbes, runAccessControlProbesDetailed } from "./accessControlProbe.js";
import { mayBePrivateRecord, nonexistentVariant } from "./accessControlIdentifiers.js";
import { sameIdentity, looksLikeShell } from "./accessControlCompare.js";
import { serve, closeServers } from "./testkit";

afterEach(closeServers);

// False positives on shells, public pages and a duplicated account. Each "stays quiet" test failed
// on the first version, which compared layout HTML and counted any id-shaped URL as a record.

const OWNER = { cookie: "sid=owner" };
const OTHER = { cookie: "sid=other" };

function who(req: http.IncomingMessage): "owner" | "other" | "anon" {
  const c = req.headers.cookie ?? "";
  return c.includes("sid=owner") ? "owner" : c.includes("sid=other") ? "other" : "anon";
}

const nav = Array.from({ length: 60 }, (_, i) => `<a href="/p${i}">Menu item number${i} label${i}</a>`).join(" ");
const probe = (port: number, urls: string[], creds: { primary?: object; secondary?: object } = {}) =>
  runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
    runAccessControlProbes({ urls, primary: (creds.primary ?? OWNER) as never, secondary: (creds.secondary ?? OTHER) as never }),
  );
const names = (f: { severity: string; name: string }[]) => f.map((x) => `${x.severity}:${x.name}`);

describe("a gated app shell is not a shared record", () => {
  const shell = `<html><body><nav>${nav}</nav><main><div id="root">Order details are on their way</div></main><script>fetch('/api/orders/1042')</script></body></html>`;

  it("stays quiet when every id gets the same layout and the record loads by script", async () => {
    const port = await serve((req, res) => {
      if (who(req) === "anon") { res.writeHead(401).end("<h1>Please log in</h1>"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(shell);
    });
    expect(names(await probe(port, [`http://localhost:${port}/orders/1042`]))).toEqual([]);
  });

  it("stays quiet when the shell shows a loading skeleton", async () => {
    const port = await serve((req, res) => {
      if (who(req) === "anon") { res.writeHead(401).end("<h1>Please log in</h1>"); return; }
      const id = /\/orders\/(\d+)/.exec(req.url ?? "")?.[1];
      // Only ids 1041-1043 are real, but every one of them renders the same skeleton.
      res.writeHead(200, { "content-type": "text/html" }).end(
        `<html><body><nav>${nav}</nav><main>Loading order details, please wait while we fetch your data ${id === "1042" ? "" : ""}</main></body></html>`,
      );
    });
    expect(names(await probe(port, [`http://localhost:${port}/orders/1042`]))).toEqual([]);
  });

  it("stays quiet when a nonexistent id gets the same page as the record", async () => {
    // No loading text at all: the only evidence it is a shell is that a made-up id renders it too.
    const port = await serve((req, res) => {
      if (who(req) === "anon") { res.writeHead(401).end("<h1>Please log in</h1>"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(shell);
    });
    const r = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runAccessControlProbesDetailed({ urls: [`http://localhost:${port}/orders/1042`], primary: OWNER, secondary: OTHER }),
    );
    expect(r.findings).toEqual([]);
    expect(r.compared).toBeGreaterThanOrEqual(1);
  });

  it("still reports real records that differ by id when a made-up id is refused", async () => {
    const port = await serve((req, res) => {
      if (who(req) === "anon") { res.writeHead(401).end("<h1>Please log in</h1>"); return; }
      const id = /\/orders\/(\d+)/.exec(req.url ?? "")?.[1];
      if (id !== "1042" && id !== "1043" && id !== "1041") { res.writeHead(404).end("Not found"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(
        `<html><body><h1>Order ${id}</h1><p>Ada Lovelace, 12 Analytical Street London, total 42.00 paid in full, shipped by courier</p>` +
          `<p>Items: analytical engine punch cards, brass gears, ink and paper reams for the difference engine</p></body></html>`,
      );
    });
    const f = await probe(port, [`http://localhost:${port}/orders/1042`]);
    expect(names(f)).toContain("critical:Broken Object-Level Authorisation (IDOR)");
    expect(names(f)).toContain("critical:Records Enumerable by Editing the Identifier");
  });
});

describe("public pages are not private records readable without signing in", () => {
  const page = (title: string) =>
    `<html><body><h1>${title}</h1><p>A durable item for everyday use, available in three colours with free shipping over fifty dollars.</p><p>Reviews and specifications follow below for shoppers everywhere.</p></body></html>`;

  it("stays quiet for /products/12 and a dated blog slug that everyone sees alike", async () => {
    const port = await serve((req, res) => {
      const ok = req.url === "/products/12" || req.url === "/blog/top-10-tips-2024";
      res.writeHead(ok ? 200 : 404, { "content-type": "text/html" }).end(ok ? page("Widget") : "Not found");
    });
    expect(
      names(await probe(port, [`http://localhost:${port}/products/12`, `http://localhost:${port}/blog/top-10-tips-2024`])),
    ).toEqual([]);
  });

  it("stays quiet for a page that renders the same for any id in a private-looking path", async () => {
    // Nothing distinguishes it from a catch-all: a made-up id gets the identical page.
    const port = await serve((_req, res) => { res.writeHead(200, { "content-type": "text/html" }).end(page("Anything")); });
    expect(names(await probe(port, [`http://localhost:${port}/invoices/1042`]))).toEqual([]);
  });

  it("still reports a private record readable without a session when only real ids exist", async () => {
    const port = await serve((req, res) => {
      const id = /\/invoices\/(10\d\d)$/.exec(req.url ?? "")?.[1];
      if (!id) { res.writeHead(404).end("Not found"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(
        `<html><body><h1>Invoice ${id}</h1><p>Customer Ada of Acme Industries, billing address 14 Rowan Street Bristol, total 5040 due in thirty days</p></body></html>`,
      );
    });
    expect(names(await probe(port, [`http://localhost:${port}/invoices/1042`]))).toEqual(["high:Records Readable Without Signing In"]);
  });
});

describe("the same account given twice is not two accounts", () => {
  const record = `<html><body>${Array.from({ length: 30 }, (_, i) => `item${i}`).join(" ")} Order 1042 for Ada Lovelace total forty two dollars paid in full shipped</body></html>`;
  const serveOrders = () =>
    serve((req, res) => {
      if (!(req.headers.cookie ?? "").includes("sid=me")) { res.writeHead(401).end("<h1>Please log in</h1>"); return; }
      if (!/\/orders\/10\d\d$/.test(req.url ?? "")) { res.writeHead(404).end("Not found"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(record);
    });

  it("reports nothing and records why, instead of IDOR", async () => {
    const port = await serveOrders();
    const same = { cookie: "sid=me" };
    const r = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runAccessControlProbesDetailed({ urls: [`http://localhost:${port}/orders/1042`], primary: same, secondary: { cookie: " sid=me " } }),
    );
    expect(r.findings).toEqual([]);
    expect(r.compared).toBe(0);
    expect(r.notTested).toMatch(/same account/i);
  });

  it("still reports IDOR for two genuinely different sessions on the same app", async () => {
    const port = await serve((req, res) => {
      if (who(req) === "anon") { res.writeHead(401).end("<h1>Please log in</h1>"); return; }
      if (!/\/orders\/10\d\d$/.test(req.url ?? "")) { res.writeHead(404).end("Not found"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(record);
    });
    expect(names(await probe(port, [`http://localhost:${port}/orders/1042`]))).toContain("critical:Broken Object-Level Authorisation (IDOR)");
  });
});

describe("helpers", () => {
  it("sameIdentity compares normalised cookies, headers and Authorization", () => {
    expect(sameIdentity({ cookie: "a=1; b=2" }, { cookie: "b=2;a=1" })).toBe(true);
    expect(sameIdentity({ headers: { Authorization: "Bearer x" } }, { headers: { authorization: "Bearer x " } })).toBe(true);
    expect(sameIdentity({ cookie: "sid=a" }, { cookie: "sid=b" })).toBe(false);
    expect(sameIdentity({ headers: { Authorization: "Bearer x" } }, { headers: { Authorization: "Bearer y" } })).toBe(false);
    expect(sameIdentity({}, {})).toBe(false);
  });

  it("mayBePrivateRecord excludes public collections and slugs", () => {
    expect(mayBePrivateRecord("https://a.example/orders/1042")).toBe(true);
    expect(mayBePrivateRecord("https://a.example/invoice?id=7")).toBe(true);
    expect(mayBePrivateRecord("https://a.example/products/12")).toBe(false);
    expect(mayBePrivateRecord("https://a.example/blog/top-10-tips-2024")).toBe(false);
  });

  it("nonexistentVariant swaps the identifier only", () => {
    expect(nonexistentVariant("https://a.example/orders/1042")).toBe("https://a.example/orders/999999937");
    expect(nonexistentVariant("https://a.example/invoice?id=7")).toBe("https://a.example/invoice?id=999999937");
    expect(nonexistentVariant("https://a.example/dashboard")).toBeNull();
  });

  it("looksLikeShell spots loading text but not record content", () => {
    expect(looksLikeShell("<main>Loading order details, please wait</main>")).toBe(true);
    expect(looksLikeShell("<main>Order 1042 for Ada, total 42.00</main>")).toBe(false);
  });
});
