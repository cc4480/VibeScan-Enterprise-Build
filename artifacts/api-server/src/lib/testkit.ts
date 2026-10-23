/**
 * Loopback servers for tests that drive the real scan HTTP layer against a stub target.
 * Shared by the probe test files so each does not carry its own copy. Register
 * `afterEach(closeServers)` in every file that calls serve().
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export const servers: http.Server[] = [];

/** Listens on an ephemeral port of `host` (127.0.0.2 stands in for "another host") and returns the port. */
export async function serve(handler: http.RequestListener, host = "127.0.0.1"): Promise<number> {
  const srv = http.createServer(handler);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, host, r));
  return (srv.address() as AddressInfo).port;
}

export async function closeServers(): Promise<void> {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
}

export function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
  });
}
