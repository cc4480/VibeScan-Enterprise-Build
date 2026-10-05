/**
 * A forward proxy that only ever connects to addresses it has just vetted, for the headless browser.
 *
 * Chromium and Playwright resolve names themselves, so a DNS server that answers a public address to
 * the scanner's check and 127.0.0.1 to the browser's own lookup would get the browser to fetch an
 * internal page. Pointing the browser at this proxy moves name resolution here: every CONNECT and
 * plain-HTTP request is resolved through vettedLookup, which refuses a name with any private answer
 * and hands the socket the same addresses it judged (see pinnedDispatcher.ts).
 *
 * It binds to 127.0.0.1 only and forwards nothing the scanner's own HTTP client would refuse.
 */
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { vettedLookup } from "./pinnedDispatcher";
import { isPrivateAddress, privateTargetsAllowed } from "./ssrfGuard";

const CONNECT_TIMEOUT_MS = 15_000;
const IDLE_TIMEOUT_MS = 60_000;

const HOP_BY_HOP = new Set([
  "connection", "proxy-connection", "proxy-authorization", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade",
]);

/** A literal address skips DNS, so the lookup never sees it; judge it here. */
function literalRefused(host: string): boolean {
  return net.isIP(host) !== 0 && !privateTargetsAllowed() && isPrivateAddress(host);
}

function splitHostPort(authority: string, defaultPort: number): { host: string; port: number } | null {
  const m = /^(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/.exec(authority);
  if (!m) return null;
  const host = (m[1] ?? m[2])!.toLowerCase().replace(/\.$/, "");
  const port = m[3] ? Number(m[3]) : defaultPort;
  return port > 0 && port < 65536 ? { host, port } : null;
}

export interface VettedProxy {
  /** e.g. "http://127.0.0.1:41234", for Playwright's `proxy.server`. */
  server: string;
  close(): Promise<void>;
}

export async function startVettedProxy(): Promise<VettedProxy> {
  const server = http.createServer((req, res) => {
    let target: URL;
    try {
      target = new URL(req.url ?? "");
    } catch {
      res.writeHead(400).end();
      return;
    }
    if (target.protocol !== "http:") {
      res.writeHead(400).end();
      return;
    }
    const host = target.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (literalRefused(host)) {
      res.writeHead(403).end("blocked target address");
      return;
    }
    const headers: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP_BY_HOP.has(k)) headers[k] = v;
    const upstream = http.request(
      { host, port: Number(target.port) || 80, method: req.method, path: target.pathname + target.search, headers, lookup: vettedLookup as never },
      (up) => {
        res.writeHead(up.statusCode ?? 502, up.headers);
        up.pipe(res);
      },
    );
    upstream.setTimeout(IDLE_TIMEOUT_MS, () => upstream.destroy());
    upstream.on("error", () => {
      if (!res.headersSent) res.writeHead(502).end("blocked or unreachable");
      else res.destroy();
    });
    req.pipe(upstream);
  });

  server.on("connect", (req, client, head) => {
    const hp = splitHostPort(req.url ?? "", 443);
    const refuse = (status: string) => {
      client.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
    };
    if (!hp) return refuse("400 Bad Request");
    if (literalRefused(hp.host)) return refuse("403 Forbidden");

    const upstream = net.connect({ host: hp.host, port: hp.port, lookup: vettedLookup as never });
    upstream.setTimeout(CONNECT_TIMEOUT_MS, () => upstream.destroy());
    upstream.once("connect", () => {
      upstream.setTimeout(IDLE_TIMEOUT_MS, () => upstream.destroy());
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on("error", () => (client.writable ? refuse("502 Bad Gateway") : client.destroy()));
    client.on("error", () => upstream.destroy());
    client.on("close", () => upstream.destroy());
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  server.unref();
  return {
    server: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }),
  };
}
