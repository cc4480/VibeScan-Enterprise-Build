import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import dns from "node:dns";
import dnsPromises from "node:dns/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { Agent, fetch as undiciFetch } from "undici";
import { vettedLookup, scanDispatcher, strictDispatcher } from "./pinnedDispatcher";
import { scanFetch } from "./http";
import { _clearResolveCache } from "./ssrfGuard";

type Answer = { address: string; family: number };
const lookupOnce = (answers: Answer[]) =>
  new Promise<{ err: NodeJS.ErrnoException | null; addrs?: unknown }>((resolve) =>
    vettedLookup("x.test", { all: true }, (err, addrs) => resolve({ err, addrs })),
  ).then((r) => ({ ...r, answers }));

const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
beforeEach(() => { delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"]; });
afterEach(() => {
  if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
  vi.restoreAllMocks();
  _clearResolveCache();
});

function mockConnectLookup(answers: Answer[]) {
  vi.spyOn(dns, "lookup").mockImplementation(((_h: string, _o: unknown, cb: (e: null, a: Answer[]) => void) =>
    cb(null, answers)) as never);
}

describe("vettedLookup", () => {
  it("refuses a name that answers a private address", async () => {
    mockConnectLookup([{ address: "127.0.0.1", family: 4 }]);
    const r = await lookupOnce([]);
    expect(r.err?.message).toMatch(/blocked target address/);
  });

  it("refuses a name when any one answer is private", async () => {
    mockConnectLookup([{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.5", family: 4 }]);
    expect((await lookupOnce([])).err).not.toBeNull();
  });

  it("hands back public answers", async () => {
    mockConnectLookup([{ address: "93.184.216.34", family: 4 }]);
    const r = await lookupOnce([]);
    expect(r.err).toBeNull();
    expect(r.addrs).toEqual([{ address: "93.184.216.34", family: 4 }]);
  });
});

describe("a rebinding name at connect time", () => {
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
      mockConnectLookup([{ address: "127.0.0.1", family: 4 }]);
      const agent = new Agent({ connect: { lookup: dns.lookup as never } });
      const res = await undiciFetch(`http://rebind.attacker.test:${port}/`, { dispatcher: agent });
      expect(await res.text()).toBe("internal");
      expect(hits()).toBe(1);
    });
  });

  it("the scanner's agent refuses the same name and never connects", async () => {
    await withLoopbackServer(async (port, hits) => {
      mockConnectLookup([{ address: "127.0.0.1", family: 4 }]);
      await expect(undiciFetch(`http://rebind.attacker.test:${port}/`, { dispatcher: scanDispatcher })).rejects.toThrow();
      expect(hits()).toBe(0);
    });
  });

  it("scanFetch sends its requests through that agent", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
    vi.spyOn(dnsPromises, "lookup").mockResolvedValue([{ address: "93.184.216.34", family: 4 }] as never);
    await scanFetch("http://example.com/");
    expect((spy.mock.calls[0]![1] as { dispatcher?: unknown }).dispatcher).toBe(scanDispatcher);
  });
});

describe("strictDispatcher", () => {
  it("refuses a rebinding answer for a non-scan request, even with the private-target opt-in on", async () => {
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    mockConnectLookup([{ address: "93.184.216.34", family: 4 }, { address: "127.0.0.1", family: 4 }]);
    await expect(
      undiciFetch("http://rebind.test/", { dispatcher: strictDispatcher }),
    ).rejects.toThrow();
  });
});
