import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  isPrivateAddress,
  isHostnameSafeSync,
  checkUrlSafe,
  checkScanTarget,
  _clearResolveCache,
} from "./ssrfGuard";

// dns.lookup is the only thing in here that touches the network. Stubbing it
// keeps these tests hermetic and lets us assert the fail-closed behaviour,
// which is impossible to trigger reliably against real DNS.
vi.mock("node:dns/promises", () => ({
  default: {},
  lookup: vi.fn(),
}));

import * as dns from "node:dns/promises";
const lookup = dns.lookup as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  _clearResolveCache();
  lookup.mockReset();
});

afterEach(() => {
  delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
});

describe("isPrivateAddress", () => {
  it("catches every private IPv4 range we care about", () => {
    for (const addr of [
      "127.0.0.1",
      "10.0.0.5",
      "172.16.4.1",
      "172.31.255.255",
      "192.168.1.1",
      "169.254.169.254", // cloud metadata
      "100.64.0.1",      // CGNAT
      "0.0.0.0",
    ]) {
      expect(isPrivateAddress(addr), addr).toBe(true);
    }
  });

  it("allows ordinary public addresses", () => {
    for (const addr of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.15.0.1", "172.32.0.1"]) {
      expect(isPrivateAddress(addr), addr).toBe(false);
    }
  });

  it("catches IPv6 loopback and unique-local", () => {
    for (const addr of ["::1", "fd00::1", "fe80::1", "[::1]"]) {
      expect(isPrivateAddress(addr), addr).toBe(true);
    }
  });

  it("unwraps IPv4-mapped IPv6 rather than reading it as a public string", () => {
    // The classic bypass: same destination, second spelling.
    expect(isPrivateAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isPrivateAddress("::ffff:169.254.169.254")).toBe(true);
    expect(isPrivateAddress("::ffff:8.8.8.8")).toBe(false);
  });
});

describe("isHostnameSafeSync", () => {
  it("blocks known-internal names and suffixes", () => {
    for (const host of [
      "localhost",
      "metadata.google.internal",
      "169.254.169.254",
      "printer.local",
      "db.internal",
      "intranet", // bare label, no dot
    ]) {
      expect(isHostnameSafeSync(host), host).toBe(false);
    }
  });

  it("passes public-looking names through for DNS checking", () => {
    expect(isHostnameSafeSync("example.com")).toBe(true);
    expect(isHostnameSafeSync("sub.example.co.uk")).toBe(true);
  });

  it("ignores a trailing dot and case", () => {
    expect(isHostnameSafeSync("LOCALHOST")).toBe(false);
    expect(isHostnameSafeSync("localhost.")).toBe(false);
  });
});

describe("checkUrlSafe", () => {
  it("rejects a literal private address without consulting DNS", async () => {
    const res = await checkUrlSafe("http://169.254.169.254/latest/meta-data/");
    expect(res.ok).toBe(false);
    expect(lookup).not.toHaveBeenCalled();
  });

  it("rejects a public name that resolves to a private address", async () => {
    // The DNS-rebinding shape: the name looks fine, the answer does not.
    lookup.mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);
    const res = await checkUrlSafe("http://rebind.example.com/");
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/private or local/);
  });

  it("rejects a name that answers with one public and one private address", async () => {
    lookup.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.1", family: 4 },
    ]);
    expect((await checkUrlSafe("http://split.example.com/")).ok).toBe(false);
  });

  it("fails closed when DNS cannot resolve the name", async () => {
    lookup.mockRejectedValue(new Error("ENOTFOUND"));
    expect((await checkUrlSafe("http://nope.example.com/")).ok).toBe(false);
  });

  it("allows a public target over plain http", async () => {
    // http is legitimate for a scan target — "no HTTPS" is a finding we report,
    // not a reason to refuse the scan.
    lookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    expect((await checkUrlSafe("http://example.com/")).ok).toBe(true);
  });

  it("requires https only when the caller asks for it", async () => {
    lookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    expect((await checkUrlSafe("http://example.com/", { requireHttps: true })).ok).toBe(false);
    expect((await checkUrlSafe("https://example.com/", { requireHttps: true })).ok).toBe(true);
  });

  it("rejects non-http schemes", async () => {
    expect((await checkUrlSafe("file:///etc/passwd")).ok).toBe(false);
    expect((await checkUrlSafe("gopher://example.com/")).ok).toBe(false);
  });

  it("rejects unparseable input", async () => {
    expect((await checkUrlSafe("not a url")).ok).toBe(false);
  });

  it("honours the self-hosted opt-out only for callers that pass allowOptOut", async () => {
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";

    // Scan path: the operator has opted in, so their own network is fair game.
    expect((await checkUrlSafe("http://192.168.1.10/", { allowOptOut: true })).ok).toBe(true);

    // Webhook path never opts out — that flag is about scanning, not about
    // where we are willing to send data.
    expect((await checkUrlSafe("https://192.168.1.10/", { requireHttps: true })).ok).toBe(false);
  });

  it("keeps the opt-out off unless it is exactly \"true\"", async () => {
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "1";
    expect((await checkUrlSafe("http://127.0.0.1/", { allowOptOut: true })).ok).toBe(false);
  });

  it("caches a resolution rather than re-querying per request", async () => {
    lookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    await checkUrlSafe("http://example.com/a");
    await checkUrlSafe("http://example.com/b");
    expect(lookup).toHaveBeenCalledTimes(1);
  });
});

/**
 * Cases carried over from the parallel implementation that was merged into this
 * one. They cover ground the original suite did not, and one of them describes a
 * bug this module actually had: URL.hostname wraps an IPv6 literal in brackets,
 * net.isIP does not recognise that form, and every IPv6-literal target was
 * therefore refused — public ones included.
 */
describe("IPv6 literals (regression: brackets)", () => {
  beforeEach(() => {
    _clearResolveCache();
    lookup.mockReset();
  });

  it("accepts a public IPv6 literal target", async () => {
    // No DNS: an address literal is judged directly.
    expect((await checkUrlSafe("http://[2606:4700::1]/")).ok).toBe(true);
    expect(lookup).not.toHaveBeenCalled();
  });

  it("still refuses a private IPv6 literal target", async () => {
    expect((await checkUrlSafe("http://[::1]/")).ok).toBe(false);
    expect((await checkUrlSafe("http://[fd00::1]/")).ok).toBe(false);
  });

  it("treats the bracketed and bare forms alike", () => {
    expect(isHostnameSafeSync("[2606:4700::1]")).toBe(isHostnameSafeSync("2606:4700::1"));
    expect(isHostnameSafeSync("[::1]")).toBe(isHostnameSafeSync("::1"));
  });
});

describe("checkScanTarget", () => {
  beforeEach(() => {
    _clearResolveCache();
    lookup.mockReset();
  });

  it("refuses a non-http scheme", async () => {
    expect((await checkScanTarget("file:///etc/passwd")).ok).toBe(false);
  });

  it("refuses an internal address", async () => {
    expect((await checkScanTarget("http://169.254.169.254/")).ok).toBe(false);
  });

  it("accepts a public target over plain http", async () => {
    lookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    expect((await checkScanTarget("http://example.com/")).ok).toBe(true);
  });
});
