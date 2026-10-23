import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import dnsPromises from "node:dns/promises";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { startVettedProxy, type VettedProxy } from "./vettedProxy";

/**
 * The proxy the headless browser goes through. "rebind.localtest.me" is a real public name that answers 127.0.0.1, so the
 * proxy's own lookup really finds a private address behind a name. The name-based tests skip when public DNS cannot be reached.
 */
const REBIND = "rebind.localtest.me";
let dnsUp = false;
try { dnsUp = (await dnsPromises.lookup(REBIND, { all: true })).some((a) => a.address === "127.0.0.1"); } catch { /* offline */ }

let proxy: VettedProxy;
let proxyPort = 0;
let hits = 0;
let origin: http.Server;
let originPort = 0;
const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];

beforeAll(async () => {
  origin = http.createServer((_q, res) => { hits++; res.end("internal"); });
  await new Promise<void>((r) => origin.listen(0, "127.0.0.1", r));
  originPort = (origin.address() as AddressInfo).port;
  proxy = await startVettedProxy();
  proxyPort = Number(new URL(proxy.server).port);
});
afterAll(async () => { await proxy.close(); origin.close(); });
beforeEach(() => { hits = 0; delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"]; });
afterEach(() => {
  if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
});

/** Send CONNECT and, if tunnelled, a GET through it; resolves the status line and any body. */
function viaConnect(authority: string, path = "/"): Promise<{ status: string; body: string }> {
  return new Promise((resolve) => {
    const s = net.connect(proxyPort, "127.0.0.1");
    let buf = "";
    let tunnelled = false;
    s.on("connect", () => s.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`));
    s.on("data", (d) => {
      buf += d.toString();
      if (!tunnelled && buf.includes("\r\n\r\n")) {
        if (buf.startsWith("HTTP/1.1 200")) {
          tunnelled = true;
          buf = "";
          s.write(`GET ${path} HTTP/1.1\r\nHost: ${authority}\r\nConnection: close\r\n\r\n`);
        } else s.end();
      }
    });
    s.on("close", () => resolve({ status: tunnelled ? "200" : buf.split("\r\n")[0]!, body: tunnelled ? buf : "" }));
    s.setTimeout(5000, () => s.destroy());
  });
}

function viaPlain(url: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve) => {
    const req = http.request({ host: "127.0.0.1", port: proxyPort, method: "GET", path: url, headers: { Host: new URL(url).host } }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on("error", () => resolve({ status: 0, body: "" }));
    req.end();
  });
}

describe("vetted proxy", () => {
  it.skipIf(!dnsUp)("refuses a CONNECT to a name that resolves to loopback, and never reaches the server", async () => {
    const r = await viaConnect(`${REBIND}:${originPort}`);
    expect(r.status).not.toBe("200");
    expect(hits).toBe(0);
  });

  it("refuses a literal private address in a CONNECT", async () => {
    expect((await viaConnect("169.254.169.254:80")).status).toMatch(/403/);
    expect((await viaConnect("[::1]:80")).status).toMatch(/403/);
  });

  it.skipIf(!dnsUp)("refuses a plain-HTTP request to a private name or literal", async () => {
    expect((await viaPlain(`http://${REBIND}:${originPort}/`)).status).not.toBe(200);
    expect((await viaPlain(`http://127.0.0.1:${originPort}/`)).status).toBe(403);
    expect(hits).toBe(0);
  });

  it.skipIf(!dnsUp)("tunnels and forwards when the operator has opted in to private targets", async () => {
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    const c = await viaConnect(`${REBIND}:${originPort}`);
    expect(c.status).toBe("200");
    expect(c.body).toContain("internal");
    const p = await viaPlain(`http://${REBIND}:${originPort}/`);
    expect(p).toEqual({ status: 200, body: "internal" });
    expect(hits).toBe(2);
  });
});
