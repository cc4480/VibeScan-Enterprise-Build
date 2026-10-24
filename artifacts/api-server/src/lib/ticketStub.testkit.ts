/**
 * A real HTTP server that answers like Linear and Jira Cloud, for tests of the code that files tickets.
 *
 * Both are third parties and a test must not depend on them, spend their rate limits, or need an account on them. The code
 * under test is pointed here (LINEAR_API_URL, JIRA_BASE_URL, see ticketEndpoints.ts), so the real clients make real requests
 * over a real socket: URLs, headers, bodies and status handling are all production code. This server only decides what the
 * provider would answer, and records what it was asked.
 *
 * One listener serves both under path prefixes: /linear and /jira.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export interface Recorded {
  method: string;
  host: "linear" | "jira";
  path: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface Reply { status?: number; json?: unknown; text?: string; delayMs?: number }
type Handler = (r: Recorded) => Reply | Promise<Reply>;

export interface TicketStub {
  linear: string;
  jira: string;
  requests: Recorded[];
  /** Answer `method host path` (a string for an exact match or a RegExp) with `reply`. Later routes win. */
  on(method: string, host: Recorded["host"], path: string | RegExp, reply: Reply | Handler): void;
  clear(): void;
  stop(): Promise<void>;
}

export async function startTicketStub(): Promise<TicketStub> {
  const routes: Array<{ method: string; host: Recorded["host"]; path: string | RegExp; reply: Reply | Handler }> = [];
  const requests: Recorded[] = [];
  const sockets = new Set<import("node:net").Socket>();

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const m = /^\/(linear|jira)(\/[^?]*)?/.exec(req.url ?? "/");
      const host = (m?.[1] ?? "linear") as Recorded["host"];
      const path = m?.[2] ?? "/";
      const rec: Recorded = { method: req.method ?? "GET", host, path, headers: req.headers, body: Buffer.concat(chunks).toString("utf8") };
      requests.push(rec);

      const hit = [...routes].reverse().find((r) => r.method === rec.method && r.host === host && (typeof r.path === "string" ? r.path === path : r.path.test(path)));
      const reply: Reply = hit ? (typeof hit.reply === "function" ? await hit.reply(rec) : hit.reply) : { status: 404, json: { message: "Not Found" } };
      if (reply.delayMs) await new Promise((r) => setTimeout(r, reply.delayMs));
      res.statusCode = reply.status ?? 200;
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

  const stub: TicketStub = {
    linear: `${origin}/linear`,
    jira: `${origin}/jira`,
    requests,
    on: (method, host, path, reply) => { routes.push({ method, host, path, reply }); },
    clear: () => { routes.length = 0; requests.length = 0; },
    stop: () => new Promise<void>((resolve) => { for (const sock of sockets) sock.destroy(); server.close(() => resolve()); }),
  };
  process.env["LINEAR_API_URL"] = stub.linear;
  process.env["JIRA_BASE_URL"] = stub.jira;
  return stub;
}

/** Puts the endpoints back to Linear's and Jira's own. */
export function useRealTickets(): void {
  delete process.env["LINEAR_API_URL"];
  delete process.env["JIRA_BASE_URL"];
}
