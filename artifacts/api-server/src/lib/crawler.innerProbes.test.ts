import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { crawlAndCheck } from "./crawler.js";

// Inner-route probes (`<dir>/.env`, `<dir>/config.json`, ...) need the same
// guards as root probing: an app shell answering 200 for every path is not an
// exposed file, and a file only counts when its content has the file's shape.

const servers: http.Server[] = [];
type Reply = { ct?: string; body: string };
async function serve(reply: (path: string) => Reply | null): Promise<string> {
  const srv = http.createServer((req, res) => {
    const r = reply((req.url ?? "/").split("?")[0]!);
    if (!r) { res.writeHead(404, { "content-type": "text/plain" }).end("not found"); return; }
    res.writeHead(200, { "content-type": r.ct ?? "text/html" }).end(r.body);
  });
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const ROOT = `<html><head><title>Acme</title></head><body>${"<p>x</p>".repeat(30)}
<a href="/app/dashboard">d</a> <a href="/docs/guide">g</a></body></html>`;

async function crawl(reply: (path: string) => Reply | null) {
  const origin = await serve((p) => (p === "/" ? { body: ROOT } : reply(p)));
  const r = await crawlAndCheck(`${origin}/`, ROOT, { "content-type": "text/html" }, [], 5);
  return r.vulnerabilities.filter((v) => /Inner Route/.test(v.name));
}

const PAGE = "<html><head><title>Page</title></head><body>page</body></html>";

describe("inner-route probes on a catch-all site", () => {
  it("reports nothing when every path returns an HTML app shell mentioning errors", async () => {
    const found = await crawl((p) => ({
      body: `<!doctype html><html><head><title>App ${p.length}</title></head><body>Error boundary, warn, trace, "swagger", "paths", {"a":1}` +
        `${"x".repeat(200 + p.length * 37)}</body></html>`,
    }));
    expect(found).toEqual([]);
  });

  it("reports nothing for look-alike bodies that are not the files", async () => {
    const found = await crawl((p) => {
      if (p === "/app/dashboard" || p === "/docs/guide") return { body: PAGE };
      if (p.endsWith("/debug.log")) return { ct: "text/plain", body: "Sorry, an error occurred while loading this page. Please warn support and trace your steps.".repeat(3) };
      if (p.endsWith("/.env")) return { ct: "application/json", body: '{"status":"ok","message":"nothing to see here"}' };
      if (p.endsWith("/config.json")) return { ct: "application/json", body: '{"apiUrl":"https://api.acme.test","firebase":{"apiKey":"AIzaPublicClientKey"},"flags":{"beta":true}}' };
      if (p.endsWith("/swagger.json")) return { ct: "application/json", body: '{"swagger":"see docs","title":"not a spec"}' };
      return null;
    });
    expect(found).toEqual([]);
  });
});

describe("inner-route probes still find real exposures", () => {
  const real = (p: string): Reply | null => {
    if (p === "/app/dashboard" || p === "/docs/guide") return { body: PAGE };
    if (p.endsWith("/.env")) return { ct: "text/plain", body: "# prod\nDATABASE_URL=postgres://u:p@db/x\nJWT_SECRET=abcdef123456\n" };
    if (p.endsWith("/config.json")) return { ct: "application/json", body: '{"db_password":"hunter2hunter2","host":"db"}' };
    if (p.endsWith("/debug.log")) return { ct: "text/plain", body: "[2025-01-01 12:00:00] ERROR: db connection failed at db.js:42\n[2025-01-01 12:00:01] WARN: retry 1 of 3\n[2025-01-01 12:00:02] DEBUG: pool exhausted\n" };
    if (p.endsWith("/swagger.json")) return { ct: "application/json", body: JSON.stringify({ swagger: "2.0", info: { title: "x", version: "1" }, paths: { "/u": {} } }) };
    return null;
  };

  it("flags .env, secret config.json, debug log and swagger spec with an honest API-doc severity", async () => {
    const found = await crawl(real);
    const by = (n: RegExp) => found.find((v) => n.test(v.name));
    expect(by(/Environment File/)?.severity).toBe("critical");
    expect(by(/Configuration File/)).toBeDefined();
    expect(by(/Debug Log/)).toBeDefined();
    expect(by(/API Documentation/)?.severity).toBe("info");
  });

  it("files one finding per file type across directories and lists the other locations", async () => {
    const found = await crawl(real);
    expect(found.filter((v) => /Environment File/.test(v.name))).toHaveLength(1);
    const env = found.find((v) => /Environment File/.test(v.name))!;
    expect(env.evidence).toContain("/app/.env");
    expect(env.evidence).toContain("/docs/.env");
  });
});
