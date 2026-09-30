import { afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";

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

export const OWNER = { cookie: "sid=owner" };
export const OTHER = { cookie: "sid=other" };

export function who(req: http.IncomingMessage): "owner" | "other" | "anon" {
  const c = req.headers.cookie ?? "";
  if (c.includes("sid=owner")) return "owner";
  if (c.includes("sid=other")) return "other";
  return "anon";
}

/** A real record store: ids 1000-1099 exist, anything else (including a made-up id) is not found. */
export const exists = (req: http.IncomingMessage) => /\/invoices\/10\d\d(\?|$)/.test(req.url ?? "");

export const loginPage = "<h1>Please log in</h1><form><input type='password' name='p'></form>";

/** Enough distinct words that the similarity comparison has something to work on. */
export function record(owner: string, extra = "") {
  return `<html><body><h1>Invoice 1042</h1>
    <p>Customer ${owner} of Acme Industries, billing address 14 Rowan Street Bristol</p>
    <p>Line items: consulting retainer, hosting, support hours, travel expenses</p>
    <p>Totals: subtotal 4200, tax 840, due 5040, payable within thirty days</p>
    ${extra}</body></html>`;
}
