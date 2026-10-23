import { describe, it, expect, afterEach, beforeEach } from "vitest";
import dns from "node:dns";
import dnsPromises from "node:dns/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { Agent, fetch as undiciFetch } from "undici";
import { vettedLookup, scanDispatcher, strictDispatcher } from "./pinnedDispatcher";
import { scanFetch } from "./http";
import { _clearResolveCache } from "./ssrfGuard";

/**
 * The agents that vet the address a socket really opens to. The names used are real:
 *   rebind.localtest.me  public DNS that answers 127.0.0.1 (a name that leads somewhere private at connect time)
 *   example.com          an ordinary public name
 * The suite skips when public DNS cannot be reached.
 */
const REBIND = "rebind.localtest.me";
let dnsUp = false;
try {
  dnsUp = (await dnsPromises.lookup(REBIND, { all: true })).some((a) => a.address === "127.0.0.1")
    && (await dnsPromises.lookup("example.com", { all: true })).length > 0;
} catch { /* offline */ }
const suite = dnsUp ? describe : describe.skip;

const lookupOf = (name: string) =>
  new Promise<{ err: NodeJS.ErrnoException | null; addrs?: unknown }>((resolve) =>
    vettedLookup(name, { all: true }, (err, addrs) => resolve({ err, addrs })),
  );

const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
beforeEach(() => { delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"]; });
afterEach(() => {
  if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
  _clearResolveCache();
});

suite("vettedLookup", () => {
  it("refuses a name that answers a private address", async () => {
    const r = await lookupOf(REBIND);
    expect(r.err?.message).toMatch(/blocked target address/);
  });

  it("hands back public answers", async () => {
    const r = await lookupOf("example.com");
    expect(r.err).toBeNull();
    const addrs = r.addrs as Array<{ address: string }>;
    expect(addrs.length).toBeGreaterThan(0);
    expect(addrs.every((a) => !/^(127\.|10\.|192\.168\.|::1$)/.test(a.address))).toBe(true);
  });
});

suite("a rebinding name at connect time", () => {
  async function withLoopbackServer(run: (port: number, hits: () => number) => Promise<void>) {
    let hits = 0;
    const server = http.createServer((_q, res) => { hits++; res.end("internal"); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    try {
      await run((server.address() as AddressInfo).port, () => hits);
    } finally {
      server.close();
    }
  }

  it("an unguarded agent follows the name to loopback (the hole)", async () => {
    await withLoopbackServer(async (port, hits) => {
      const agent = new Agent({ connect: { lookup: dns.lookup as never } });
      const res = await undiciFetch(`http://${REBIND}:${port}/`, { dispatcher: agent });
      expect(await res.text()).toBe("internal");
      expect(hits()).toBe(1);
    });
  });

  it("the scanner's agent refuses the same name and never connects", async () => {
    await withLoopbackServer(async (port, hits) => {
      await expect(undiciFetch(`http://${REBIND}:${port}/`, { dispatcher: scanDispatcher })).rejects.toThrow();
      expect(hits()).toBe(0);
    });
  });

  it("scanFetch sends its requests through that agent: the same name is refused, so it returns nothing", async () => {
    await withLoopbackServer(async (port, hits) => {
      expect(await scanFetch(`http://${REBIND}:${port}/`)).toBeNull();
      expect(hits()).toBe(0);
    });
  });
});

suite("strictDispatcher", () => {
  it("refuses a name that leads to loopback for a non-scan request, even with the private-target opt-in on", async () => {
    // With the opt-in on, the scan agent follows the name to loopback; the strict agent, used for requests a user
    // supplied the address of (webhooks), still refuses it. The two together are the contrast.
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    let hits = 0;
    const server = http.createServer((_q, res) => { hits++; res.end("internal"); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    try {
      const viaScan = await undiciFetch(`http://${REBIND}:${port}/`, { dispatcher: scanDispatcher });
      expect(await viaScan.text()).toBe("internal");
      expect(hits).toBe(1);
      await expect(undiciFetch(`http://${REBIND}:${port}/`, { dispatcher: strictDispatcher })).rejects.toThrow();
      expect(hits).toBe(1); // the strict agent never connected
    } finally {
      server.close();
    }
  });
});
