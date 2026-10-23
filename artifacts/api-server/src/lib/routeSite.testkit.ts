/**
 * A real web server on loopback standing in for the site a probe scans, with the answers set per test.
 *
 * Probes request real URLs over a real socket; this server only decides what the site would answer, and records what it
 * was asked (method, path, query, the Host header, headers and body). Anything not set is a 404, as on a site with
 * nothing at that path.
 *
 * `useRouteSite()` starts it for the calling test file and clears it before each test.
 */
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { beforeEach, afterAll } from "vitest";

export interface Seen {
  method: string;
  path: string;
  url: string;
  host: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface Answer {
  status?: number;
  body?: string;
  /** Content type; JSON by default, since most probed documents are. */
  ct?: string;
  headers?: Record<string, string>;
  /** Cut the connection without answering, as an unreachable site does. */
  drop?: boolean;
}

export type AnswerFn = (req: Seen) => Answer | undefined | Promise<Answer | undefined>;

export interface RouteSite {
  /** http://127.0.0.1:PORT, with no trailing slash. */
  origin: string;
  port: number;
  /** Answers by exact path (any method). Replaces earlier routes. */
  routes(table: Record<string, Answer>): void;
  /** Answers every request not matched by a route; return undefined for a 404. */
  otherwise(fn: AnswerFn): void;
  /** Every request received, in order. */
  seen: Seen[];
  reset(): void;
  stop(): Promise<void>;
}

export async function startRouteSite(): Promise<RouteSite> {
  const sockets = new Set<Socket>();
  let table: Record<string, Answer> = {};
  let fallback: AnswerFn | null = null;
  const seen: Seen[] = [];

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const url = req.url ?? "/";
      const q = url.indexOf("?");
      const rec: Seen = {
        method: req.method ?? "GET", path: q < 0 ? url : url.slice(0, q), url,
        host: String(req.headers.host ?? ""), headers: req.headers, body: Buffer.concat(chunks).toString("utf8"),
      };
      seen.push(rec);
      const answer = table[rec.path] ?? (fallback ? await fallback(rec) : undefined);
      if (answer?.drop) { req.socket.destroy(); return; }
      if (!answer) { res.writeHead(404, { "content-type": "text/plain" }).end("Not Found"); return; }
      res.writeHead(answer.status ?? 200, { "content-type": answer.ct ?? "application/json", ...(answer.headers ?? {}) });
      res.end(answer.body ?? "");
    });
  });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as AddressInfo).port;

  return {
    origin: `http://127.0.0.1:${port}`,
    port,
    routes: (t) => { table = t; },
    otherwise: (fn) => { fallback = fn; },
    seen,
    reset: () => { table = {}; fallback = null; seen.length = 0; },
    stop: () => new Promise<void>((resolve) => { for (const s of sockets) s.destroy(); server.close(() => resolve()); }),
  };
}

/** Start the site for this test file, empty before every test, stopped at the end. */
export async function useRouteSite(): Promise<RouteSite> {
  const site = await startRouteSite();
  beforeEach(() => site.reset());
  afterAll(() => site.stop());
  return site;
}
