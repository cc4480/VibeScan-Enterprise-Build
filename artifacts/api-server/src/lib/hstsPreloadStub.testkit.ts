/**
 * A real HTTP server that answers like hstspreload.org's status API, for tests of the HSTS and redirect checks.
 *
 * The checks are pointed here with HSTS_PRELOAD_API_URL, so the real client makes real requests; this server only decides
 * which hosts are preloaded and records the hosts it was asked about. `mode` makes it misbehave the way a failing API does.
 */
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { beforeEach, afterAll } from "vitest";

export interface HstsPreloadStub {
  /** host -> "preloaded" | "pending" | "rejected"; any other host is "unknown". */
  statuses: Map<string, string>;
  /** "ok" answers normally; "unavailable" answers 503; "garbage" answers 200 with a body that is not JSON; "drop" cuts the connection. */
  mode: "ok" | "unavailable" | "garbage" | "drop";
  /** Every host asked about, in order. */
  asked: string[];
  reset(): void;
  stop(): Promise<void>;
}

export async function startHstsPreloadStub(): Promise<HstsPreloadStub> {
  const sockets = new Set<Socket>();
  const state: HstsPreloadStub = {
    statuses: new Map(),
    mode: "ok",
    asked: [],
    reset: () => { state.statuses.clear(); state.mode = "ok"; state.asked.length = 0; },
    stop: async () => {},
  };

  const server = http.createServer((req, res) => {
    const domain = new URL(req.url ?? "/", "http://preload.local").searchParams.get("domain") ?? "";
    state.asked.push(domain);
    if (state.mode === "drop") { req.socket.destroy(); return; }
    if (state.mode === "unavailable") { res.writeHead(503).end("unavailable"); return; }
    if (state.mode === "garbage") { res.writeHead(200, { "content-type": "application/json" }).end("<html>not json"); return; }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ name: domain, status: state.statuses.get(domain) ?? "unknown" }));
  });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  process.env["HSTS_PRELOAD_API_URL"] = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v2/status`;

  state.stop = () => new Promise<void>((resolve) => {
    delete process.env["HSTS_PRELOAD_API_URL"];
    for (const s of sockets) s.destroy();
    server.close(() => resolve());
  });
  return state;
}

/** Start the API for this test file, empty before every test, stopped at the end. */
export async function useHstsPreloadStub(): Promise<HstsPreloadStub> {
  const api = await startHstsPreloadStub();
  beforeEach(() => api.reset());
  afterAll(() => api.stop());
  return api;
}
