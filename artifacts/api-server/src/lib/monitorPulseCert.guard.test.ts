import { describe, it, expect, afterEach, beforeEach } from "vitest";
import net from "node:net";
import dns from "node:dns/promises";

// "rebind.localtest.me" is a real public name that answers 127.0.0.1: a name that resolves to a private address at
// connect time. The tests skip when it cannot be resolved (no network).
const REBIND = "rebind.localtest.me";
let resolvable = false;
try { resolvable = (await dns.lookup(REBIND, { all: true })).some((a) => a.address === "127.0.0.1"); } catch { /* offline */ }

import { probeCertDates } from "./monitorPulseCert";

const suite = resolvable ? describe : describe.skip;

suite("probeCertDates connects only to vetted addresses", () => {
  const servers: net.Server[] = [];
  let connections = 0;
  // The suite-wide config sets ALLOW_PRIVATE_SCAN_TARGETS=true for the probe tests; these tests need the guard on.
  const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];

  beforeEach(() => { delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"]; });

  afterEach(() => {
    for (const s of servers) s.close();
    servers.length = 0;
    connections = 0;
    if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
  });

  function stub(): Promise<number> {
    return new Promise((resolve) => {
      const server = net.createServer((sock) => {
        connections += 1;
        sock.on("error", () => {});
        sock.destroy();
      });
      servers.push(server);
      server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port));
    });
  }

  it("does not connect to a loopback IP literal", async () => {
    const port = await stub();
    expect(await probeCertDates(`https://127.0.0.1:${port}/`)).toBeNull();
    expect(connections).toBe(0);
  });

  it("does not connect when the name resolves to a private address", async () => {
    const port = await stub();
    expect(await probeCertDates(`https://${REBIND}:${port}/`)).toBeNull();
    expect(connections).toBe(0);
  });
});
