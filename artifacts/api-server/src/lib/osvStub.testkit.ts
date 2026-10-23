/**
 * A real HTTP server that answers like OSV.dev's /v1/query, for tests of the dependency checks.
 *
 * The checks are pointed here with OSV_API_URL, so the real client makes real requests over a real socket: the body it
 * builds, the ecosystem and version it asks about, its caching and its error handling are all production code. This server
 * only decides which packages are vulnerable, and records what it was asked.
 *
 * The test sets `vulnerable` (npm "name@version" entries answered with a stock advisory) and/or `answers` (full control, by
 * "Ecosystem:name@version"); `asked` lists every query received.
 */
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";

export type Advisory = Record<string, unknown>;

/** The advisory returned for an npm package listed in `vulnerable`. */
export const STOCK_ADVISORY: Advisory = {
  id: "GHSA-test-0001",
  aliases: ["CVE-2026-0001"],
  summary: "Prototype pollution",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
  affected: [{ ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
};

export interface OsvStub {
  vulnerable: Set<string>;
  answers: Map<string, Advisory[]>;
  asked: string[];
  /** Drop the next this-many connections without answering, as a failing network would. */
  dropNext: number;
  stop(): Promise<void>;
}

export async function startOsvStub(): Promise<OsvStub> {
  const sockets = new Set<Socket>();
  const state: OsvStub = { vulnerable: new Set(), answers: new Map(), asked: [], dropNext: 0, stop: async () => {} };

  const server = http.createServer((req, res) => {
    if (state.dropNext > 0) { state.dropNext--; req.socket.destroy(); return; }
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      let q: { version?: string; package?: { name?: string; ecosystem?: string } } = {};
      try { q = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { /* an unreadable query gets an empty answer */ }
      const name = q.package?.name ?? "";
      const ecosystem = q.package?.ecosystem ?? "";
      const version = q.version ?? "";
      const key = `${ecosystem}:${name}@${version}`;
      state.asked.push(key);
      let vulns: Advisory[] = state.answers.get(key) ?? [];
      if (vulns.length === 0 && ecosystem === "npm" && state.vulnerable.has(`${name}@${version}`)) vulns = [STOCK_ADVISORY];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(vulns.length ? { vulns } : {}));
    });
  });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  process.env["OSV_API_URL"] = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/query`;

  state.stop = () => new Promise<void>((resolve) => {
    delete process.env["OSV_API_URL"];
    for (const s of sockets) s.destroy();
    server.close(() => resolve());
  });
  return state;
}
