import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { checkActiveCors, checkOpenRedirect } from "./probes.js";

const servers: http.Server[] = [];
async function serve(h: http.RequestListener): Promise<number> {
  const srv = http.createServer(h);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const inScan = <T>(port: number, fn: () => Promise<T>) =>
  runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, fn);

describe("checkOpenRedirect — the redirect must actually leave the site", () => {
  const redirector = (loc: (q: URLSearchParams) => string) =>
    serve((req, res) => {
      const q = new URL(req.url!, "http://x").searchParams;
      res.writeHead(302, { Location: loc(q) }).end();
    });

  it.each([
    ["a canonical redirect that keeps the query string", (q: URLSearchParams) => `/en/?redirect=${encodeURIComponent(q.get("redirect") ?? "")}`],
    ["a login redirect carrying the URL as an encoded next parameter", (q: URLSearchParams) => `/login?next=${encodeURIComponent(q.get("next") ?? q.get("redirect") ?? "")}`],
    ["a path that merely contains the probe host", (q: URLSearchParams) => `/r/${(q.get("redirect") ?? "").replace(/^https?:\/\//, "")}`],
    ["a lookalike host that embeds the probe host as a subdomain of the site", () => "https://evil-redirect-probe.com.example.org/"],
  ])("does not flag %s", async (_n, loc) => {
    const port = await redirector(loc);
    expect(await inScan(port, () => checkOpenRedirect(`http://localhost:${port}/`))).toEqual([]);
  });

  it.each([
    ["an absolute URL", (q: URLSearchParams) => q.get("redirect") ?? q.get("url") ?? "/"],
    ["a protocol-relative URL", (q: URLSearchParams) => (q.get("redirect") ?? "/").replace(/^https:/, "")],
  ])("flags %s pointing at the probe host", async (_n, loc) => {
    const port = await redirector(loc);
    const found = await inScan(port, () => checkOpenRedirect(`http://localhost:${port}/`));
    expect(found).toHaveLength(1);
    expect(found[0]!.name).toBe("Open Redirect Vulnerability");
  });
});

describe("checkActiveCors — reflection without credentials is not a data-theft finding", () => {
  const cors = (creds: boolean) =>
    serve((req, res) => {
      const h: Record<string, string> = { "content-type": "text/html" };
      if (req.headers.origin) h["access-control-allow-origin"] = String(req.headers.origin);
      if (creds) h["access-control-allow-credentials"] = "true";
      res.writeHead(200, h).end("<html></html>");
    });

  it("downgrades a credential-less reflection to an honest low finding", async () => {
    const port = await cors(false);
    const found = await inScan(port, () => checkActiveCors(`http://localhost:${port}/`));
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe("low");
    expect(found[0]!.name).not.toMatch(/Without Allowlist/);
    expect(found[0]!.description).not.toMatch(/data theft|public API/i);
    expect(found[0]!.description).toMatch(/only the tested URL|this URL/i);
  });

  it("still reports critical for a reflected origin with credentials", async () => {
    const port = await cors(true);
    const found = await inScan(port, () => checkActiveCors(`http://localhost:${port}/`));
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe("critical");
  });
});
