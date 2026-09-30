import { afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";

// Real servers rather than a mocked fetch: the behaviour under test is redirect
// handling and what gets put on the wire, which a mock would only restate.
// "localhost" and "127.0.0.1" are distinct hostnames, so they stand in for
// in-scope and out-of-scope hosts without any network access.

export interface Captured {
  url: string;
  headers: http.IncomingHttpHeaders;
}

export const servers: http.Server[] = [];

export async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse, seen: Captured[]) => void,
): Promise<{ port: number; seen: Captured[] }> {
  const seen: Captured[] = [];
  const srv = http.createServer((req, res) => {
    seen.push({ url: req.url ?? "", headers: req.headers });
    handler(req, res, seen);
  });
  servers.push(srv);
  await new Promise<void>((resolve) => srv.listen(0, "127.0.0.1", resolve));
  return { port: (srv.address() as AddressInfo).port, seen };
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});
