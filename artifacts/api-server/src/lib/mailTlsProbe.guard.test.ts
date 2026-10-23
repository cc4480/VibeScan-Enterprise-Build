import { describe, it, expect, afterEach } from "vitest";
import net from "node:net";
import { probeStartTls, probeHost, probeStartTlsForTest, MAX_REPLY_BYTES } from "./mailTlsProbe";
import { strictLookup } from "./pinnedDispatcher";
import { mailTlsFindings } from "./mailTls";

describe("mail exchanger targets are not connected to when private", () => {
  const servers: net.Server[] = [];
  let connections = 0;

  afterEach(() => {
    for (const s of servers) s.close();
    servers.length = 0;
    connections = 0;
  });

  function stub(): Promise<number> {
    return new Promise((resolve) => {
      const server = net.createServer((sock) => {
        connections += 1;
        sock.write("220 stub.invalid ESMTP ready\r\n");
        sock.on("error", () => {});
      });
      servers.push(server);
      server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port));
    });
  }

  it("does not connect to an MX that is a loopback literal, and records a skipped result", async () => {
    const port = await stub();
    const r = await probeStartTls("127.0.0.1", port);
    expect(r.skipped).toMatch(/not probed/);
    expect(r.reachable).toBe(false);
    expect(connections).toBe(0);
  });

  it("does not connect to an MX named localhost", async () => {
    const port = await stub();
    const r = await probeStartTls("localhost", port);
    expect(r.skipped).toBeDefined();
    expect(connections).toBe(0);
  });

  it("probeHost skips a private MX without a finding", async () => {
    const h = await probeHost("localhost", 10);
    expect(h.ports[0]?.skipped).toBeDefined();
    expect(h.ports[0]?.reachable).toBe(false);
    expect(mailTlsFindings([h])).toEqual([]);
  });

  it("does not connect to a public name whose real DNS answer is a private address", async () => {
    // rebind.localtest.me is a real public name that resolves to 127.0.0.1. A name that answers differently to the
    // up-front check and to the connection (DNS rebinding) needs DNS this suite does not control, so that sequence
    // is not tested here; the answer being private on both lookups is.
    const port = await stub();
    const r = await probeStartTls("rebind.localtest.me", port);
    expect(r.reachable).toBe(false);
    expect(r.skipped ?? r.error).toMatch(/not probed|blocked target address/);
    expect(connections).toBe(0);
  });

  it("strictLookup refuses a private answer even when ALLOW_PRIVATE_SCAN_TARGETS is set", async () => {
    const prev = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    try {
      const lookup = strictLookup as unknown as (h: string, o: unknown, cb: (e: Error | null) => void) => void;
      const err = await new Promise<Error | null>((resolve) => lookup("localhost", { all: true }, (e) => resolve(e)));
      expect(err?.message).toMatch(/blocked target address/);
    } finally {
      if (prev === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
      else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = prev;
    }
  });

  it("stops buffering a reply that never contains a line break", async () => {
    // A server that keeps sending bytes with no newline must be cut off at the cap, not buffered forever.
    const server = net.createServer((sock) => {
      sock.on("error", () => {});
      sock.write("x".repeat(MAX_REPLY_BYTES + 1024));
    });
    servers.push(server);
    const port = await new Promise<number>((resolve) =>
      server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port)),
    );
    const r = await probeStartTlsForTest("127.0.0.1", port);
    expect(r.error).toMatch(/exceeds 8 KB/);
    expect(r.banner).toBeNull();
  });
});
