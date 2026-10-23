/**
 * A real HTTP server that answers like Supabase and Firebase, for tests of the backend-as-a-service probes.
 *
 * The probes are pointed here (SUPABASE_PROJECT_ORIGIN_TEMPLATE, FIRESTORE_API_URL, FIREBASE_STORAGE_API_URL and
 * FIREBASE_DATABASE_ORIGIN_TEMPLATE, see baasEndpoints.ts), so the real probes make real requests over a real socket:
 * the URLs they build, their headers and bodies, status handling and timeouts are all production code. This server only
 * decides what the service would answer, and records what it was asked.
 *
 * One listener serves each service under a prefix:
 *   /supabase/<ref>/...   a Supabase project        (rest/v1/<table>, auth/v1/..., storage/v1/...)
 *   /firestore/...        Cloud Firestore            (v1/projects/<id>/databases/(default)/documents/<collection>)
 *   /fbstorage/...        Firebase Storage           (v0/b/<bucket>/o)
 *   /rtdb/<name>/...      A Realtime Database        (.json)
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export interface Recorded {
  method: string;
  /** The path as received, including the service prefix and any percent-encoding. */
  path: string;
  /** Path plus query string. */
  url: string;
  query: URLSearchParams;
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
}

type Handler = (r: Recorded) => Reply | Promise<Reply>;

export interface BaasStub {
  origin: string;
  requests: Recorded[];
  /** Answer `method path` (a string for an exact match, a RegExp tested against the path) with `reply`. Later routes win. */
  on(method: string, path: string | RegExp, reply: Reply | Handler): void;
  /** Answer every request whose path matches, whatever the method, e.g. to make a service look like a locked-down one. */
  onAny(path: string | RegExp, reply: Reply | Handler): void;
  clear(): void;
  stop(): Promise<void>;
}

export async function startBaasStub(): Promise<BaasStub> {
  const routes: Array<{ method: string | null; path: string | RegExp; reply: Reply | Handler }> = [];
  const requests: Recorded[] = [];
  const sockets = new Set<import("node:net").Socket>();

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const url = req.url ?? "/";
      const q = url.indexOf("?");
      const path = q < 0 ? url : url.slice(0, q);
      const rec: Recorded = {
        method: req.method ?? "GET", path, url,
        query: new URLSearchParams(q < 0 ? "" : url.slice(q + 1)),
        headers: req.headers, body: Buffer.concat(chunks).toString("utf8"),
      };
      requests.push(rec);
      const hit = [...routes].reverse().find((r) => (r.method === null || r.method === rec.method) && (typeof r.path === "string" ? r.path === path : r.path.test(path)));
      const reply: Reply = hit ? (typeof hit.reply === "function" ? await hit.reply(rec) : hit.reply) : { status: 404, json: { message: "Not Found" } };
      if (reply.delayMs) await new Promise((r) => setTimeout(r, reply.delayMs));
      res.statusCode = reply.status ?? 200;
      for (const [k, v] of Object.entries(reply.headers ?? {})) res.setHeader(k, v);
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

  process.env["SUPABASE_PROJECT_ORIGIN_TEMPLATE"] = `${origin}/supabase/{ref}`;
  process.env["FIRESTORE_API_URL"] = `${origin}/firestore`;
  process.env["FIREBASE_STORAGE_API_URL"] = `${origin}/fbstorage`;
  process.env["FIREBASE_DATABASE_ORIGIN_TEMPLATE"] = `${origin}/rtdb/{name}`;

  return {
    origin,
    requests,
    on: (method, path, reply) => { routes.push({ method, path, reply }); },
    onAny: (path, reply) => { routes.push({ method: null, path, reply }); },
    clear: () => { routes.length = 0; requests.length = 0; },
    stop: () => new Promise<void>((resolve) => { for (const s of sockets) s.destroy(); server.close(() => resolve()); }),
  };
}

/** Puts every endpoint back to the public services. */
export function useRealBaas(): void {
  for (const k of ["SUPABASE_PROJECT_ORIGIN_TEMPLATE", "FIRESTORE_API_URL", "FIREBASE_STORAGE_API_URL", "FIREBASE_DATABASE_ORIGIN_TEMPLATE"]) delete process.env[k];
}
