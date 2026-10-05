import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import dns from "node:dns";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { startVettedProxy, type VettedProxy } from "./vettedProxy";

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
  vi.restoreAllMocks();
  if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
});

/** Make the proxy's own lookup of any name answer these addresses. */
function answer(addresses: string[]) {
  vi.spyOn(dns, "lookup").mockImplementation(((_h: string, _o: unknown, cb: (e: null, a: unknown[]) => void) =>
    cb(null, addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })))) as never);
}

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
  it("refuses a CONNECT to a name that resolves to loopback, and never reaches the server", async () => {
    answer(["127.0.0.1"]);
    const r = await viaConnect(`rebind.attacker.test:${originPort}`);
    expect(r.status).not.toBe("200");
    expect(hits).toBe(0);
  });

  it("refuses a name when one of several answers is private", async () => {
    answer(["93.184.216.34", "127.0.0.1"]);
    expect((await viaConnect(`mixed.attacker.test:${originPort}`)).status).not.toBe("200");
    expect(hits).toBe(0);
  });

  it("refuses a literal private address in a CONNECT", async () => {
    expect((await viaConnect("169.254.169.254:80")).status).toMatch(/403/);
    expect((await viaConnect("[::1]:80")).status).toMatch(/403/);
  });

  it("refuses a plain-HTTP request to a private name or literal", async () => {
    answer(["10.0.0.5"]);
    expect((await viaPlain(`http://internal.attacker.test:${originPort}/`)).status).not.toBe(200);
    expect((await viaPlain(`http://127.0.0.1:${originPort}/`)).status).toBe(403);
    expect(hits).toBe(0);
  });

  it("tunnels and forwards when the operator has opted in to private targets", async () => {
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    answer(["127.0.0.1"]);
    const c = await viaConnect(`optin.test:${originPort}`);
    expect(c.status).toBe("200");
    expect(c.body).toContain("internal");
    const p = await viaPlain(`http://optin.test:${originPort}/`);
    expect(p).toEqual({ status: 200, body: "internal" });
    expect(hits).toBe(2);
  });
});
