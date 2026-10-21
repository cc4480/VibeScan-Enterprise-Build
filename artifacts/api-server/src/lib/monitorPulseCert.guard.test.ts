import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import net from "node:net";

// "rebind.test" answers a public address to the URL check and a private one to the connect-time lookup: the DNS
// rebinding sequence. Every other name resolves normally.
vi.mock("node:dns/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns/promises")>();
  return {
    ...actual,
    lookup: (host: string, opts: unknown) =>
      host === "rebind.test"
        ? Promise.resolve([{ address: "93.184.216.34", family: 4 }])
        : (actual.lookup as (h: string, o: unknown) => Promise<unknown>)(host, opts),
  };
});

vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns")>();
  const lookup = (host: string, opts: unknown, cb: (...args: unknown[]) => void) => {
    if (host !== "rebind.test") return (actual.lookup as unknown as (...a: unknown[]) => void)(host, opts, cb);
    const wantsAll = typeof opts === "object" && opts !== null && (opts as { all?: boolean }).all === true;
    process.nextTick(() => (wantsAll ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4)));
  };
  return { ...actual, default: { ...actual, lookup } };
});

import { probeCertDates } from "./monitorPulseCert";

describe("probeCertDates connects only to vetted addresses", () => {
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

  it("does not connect when the name re-resolves to a private address at connect time", async () => {
    const port = await stub();
    expect(await probeCertDates(`https://rebind.test:${port}/`)).toBeNull();
    expect(connections).toBe(0);
  });
});
