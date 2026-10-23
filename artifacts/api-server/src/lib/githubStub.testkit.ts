/**
 * A real HTTP server that answers like GitHub, for tests of the code that talks to GitHub.
 *
 * GitHub is a third party and a test must not depend on it, spend its rate limit, or need a private repository on it.
 * The code under test is pointed here (GITHUB_API_URL, GITHUB_WEB_URL, GITHUB_RAW_URL, see githubEndpoints.ts), so the
 * real clients make real requests over a real socket: URLs, headers, bodies, status handling and timeouts are all
 * production code. This server only decides what GitHub would answer, and records what it was asked.
 *
 * One listener serves the three hosts under path prefixes: /api, /web and /raw.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export interface Recorded {
  method: string;
  /** Host kind and path as GitHub sees it, e.g. "api /repos/acme/app". */
  host: "api" | "web" | "raw";
  path: string;
  /** Path plus query string. */
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface Reply {
  status?: number;
  json?: unknown;
  text?: string;
  headers?: Record<string, string>;
  /** Wait this long before answering, to exercise timeouts. */
  delayMs?: number;
  /** Send the status line and headers and the start of a body, then never finish: a response that stalls. */
  stallBody?: boolean;
}

type Handler = (r: Recorded) => Reply | Promise<Reply>;

export interface GithubStub {
  api: string;
  web: string;
  raw: string;
  requests: Recorded[];
  /** Answer `method host path` (path is a string for an exact match or a RegExp) with `reply`. Later routes win. */
  on(method: string, host: Recorded["host"], path: string | RegExp, reply: Reply | Handler): void;
  clear(): void;
  stop(): Promise<void>;
}

export async function startGithubStub(): Promise<GithubStub> {
  const routes: Array<{ method: string; host: Recorded["host"]; path: string | RegExp; reply: Reply | Handler }> = [];
  const requests: Recorded[] = [];

  const sockets = new Set<import("node:net").Socket>();
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const url = req.url ?? "/";
      const m = /^\/(api|web|raw)(\/[^?]*)?(\?.*)?$/.exec(url);
      const host = (m?.[1] ?? "api") as Recorded["host"];
      const path = m?.[2] ?? "/";
      const rec: Recorded = { method: req.method ?? "GET", host, path, url: path + (m?.[3] ?? ""), headers: req.headers, body: Buffer.concat(chunks).toString("utf8") };
      requests.push(rec);

      const hit = [...routes].reverse().find((r) => r.method === rec.method && r.host === host && (typeof r.path === "string" ? r.path === path : r.path.test(path)));
      const reply: Reply = hit ? (typeof hit.reply === "function" ? await hit.reply(rec) : hit.reply) : { status: 404, json: { message: "Not Found" } };
      if (reply.delayMs) await new Promise((r) => setTimeout(r, reply.delayMs));
      res.statusCode = reply.status ?? 200;
      for (const [k, v] of Object.entries(reply.headers ?? {})) res.setHeader(k, v);
      if (reply.stallBody) {
        res.setHeader("content-type", "application/json");
        res.write("{");
        return; // never ends; stop() closes the connection
      }
      if (reply.json !== undefined) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(reply.json));
      } else {
        res.end(reply.text ?? "");
      }
    });
  });
  server.on("connection", (sock) => { sockets.add(sock); sock.on("close", () => sockets.delete(sock)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const stub: GithubStub = {
    api: `${origin}/api`,
    web: `${origin}/web`,
    raw: `${origin}/raw`,
    requests,
    on: (method, host, path, reply) => { routes.push({ method, host, path, reply }); },
    clear: () => { routes.length = 0; requests.length = 0; },
    stop: () => new Promise<void>((resolve) => { for (const sock of sockets) sock.destroy(); server.close(() => resolve()); }),
  };
  process.env["GITHUB_API_URL"] = stub.api;
  process.env["GITHUB_WEB_URL"] = stub.web;
  process.env["GITHUB_RAW_URL"] = stub.raw;
  return stub;
}

/** Puts the endpoints back to GitHub's own. */
export function useRealGithub(): void {
  delete process.env["GITHUB_API_URL"];
  delete process.env["GITHUB_WEB_URL"];
  delete process.env["GITHUB_RAW_URL"];
}
