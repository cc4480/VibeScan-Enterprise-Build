import { afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { ApiEndpoint } from "./apiSurface.js";

export const servers: http.Server[] = [];

export async function serve(
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

export const SESSION = { cookie: "sid=valid" };
export const signedIn = (req: http.IncomingMessage) => (req.headers.cookie ?? "").includes("sid=valid");

export const DATA = JSON.stringify({
  items: [
    { id: 1, customer: "Ada Lovelace", email: "ada@example.com", total: 5040 },
    { id: 2, customer: "Grace Hopper", email: "grace@example.com", total: 1080 },
  ],
});

export function ep(partial: Partial<ApiEndpoint> & { url: string }): ApiEndpoint {
  return { method: "GET", params: [], source: "spec", ...partial };
}
