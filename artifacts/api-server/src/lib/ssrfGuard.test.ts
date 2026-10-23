import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import dnsPromises from "node:dns/promises";
import {
  isPrivateAddress,
  isHostnameSafeSync,
  checkUrlSafe,
  checkScanTarget,
  _clearResolveCache,
} from "./ssrfGuard";

// Name resolution here is real DNS, using names chosen for what they really answer:
//   rebind.localtest.me   public DNS that answers 127.0.0.1: a public-looking name with a private answer
//   example.com           an ordinary public name
//   *.invalid             a name that is guaranteed not to exist (RFC 6761), so resolution genuinely fails
// The tests that need public DNS skip when it cannot be reached.
const REBIND = "rebind.localtest.me";
const NO_SUCH_NAME = `no-such-host-${Date.now()}.invalid`;
let dnsUp = false;
try {
  dnsUp = (await dnsPromises.lookup(REBIND, { all: true })).some((a) => a.address === "127.0.0.1")
    && (await dnsPromises.lookup("example.com", { all: true })).length > 0;
} catch { /* offline */ }
const needsDns = it.skipIf(!dnsUp);

// vitest.config.ts sets ALLOW_PRIVATE_SCAN_TARGETS=true for every test file, which turns the
// guard's opt-out on. This file tests the guard itself, so it starts with the variable unset
// (for every test, including the first) and puts the suite-wide value back when it finishes.
const SAVED_OPT_OUT = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];

beforeAll(() => {
  delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
});

afterAll(() => {
  if (SAVED_OPT_OUT === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = SAVED_OPT_OUT;
});

beforeEach(() => {
  _clearResolveCache();
});

// Tests that set the variable themselves clear it again, so each starts from unset.
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
  it("rejects a literal private address", async () => {
    // An address literal is judged directly; there is no name to look up.
    const res = await checkUrlSafe("http://169.254.169.254/latest/meta-data/");
    expect(res.ok).toBe(false);
  });

  needsDns("rejects a public-looking name that resolves to a private address", async () => {
    // The DNS-rebinding shape: the name looks fine, the answer does not.
    const res = await checkUrlSafe(`http://${REBIND}/`);
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/private or local/);
  });

  it("fails closed when DNS cannot resolve the name", async () => {
    expect((await checkUrlSafe(`http://${NO_SUCH_NAME}/`)).ok).toBe(false);
  });

  needsDns("allows a public target over plain http", async () => {
    // http is legitimate for a scan target: "no HTTPS" is a finding we report, not a reason to refuse the scan.
    expect((await checkUrlSafe("http://example.com/")).ok).toBe(true);
  });

  needsDns("requires https only when the caller asks for it", async () => {
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

  needsDns("remembers a name's verdict, so a repeat is answered the same without waiting on DNS", async () => {
    const first = await checkUrlSafe("http://example.com/a");
    const started = process.hrtime.bigint();
    const second = await checkUrlSafe("http://example.com/b");
    const tookMs = Number(process.hrtime.bigint() - started) / 1e6;
    expect(second).toEqual(first);
    expect(tookMs).toBeLessThan(5);
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
  });

  it("accepts a public IPv6 literal target", async () => {
    // No DNS: an address literal is judged directly.
    expect((await checkUrlSafe("http://[2606:4700::1]/")).ok).toBe(true);
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
  });

  it("refuses a non-http scheme", async () => {
    expect((await checkScanTarget("file:///etc/passwd")).ok).toBe(false);
  });

  it("refuses an internal address", async () => {
    expect((await checkScanTarget("http://169.254.169.254/")).ok).toBe(false);
  });

  needsDns("accepts a public target over plain http", async () => {
    expect((await checkScanTarget("http://example.com/")).ok).toBe(true);
  });
});

describe("embedded IPv4 in every IPv6 notation", () => {
  // The sibling scanner (seclayer.io2026) had the fully exploitable version of
  // this: its mapped check matched only the dotted form, and Node's URL parser
  // rewrites [::ffff:127.0.0.1] into [::ffff:7f00:1], so every internal range
  // was reachable in hex. SecScan's blanket ^::ffff: pattern covered that case,
  // but two other embedding forms still reached the pattern list intact.
  it.each([
    ["::ffff:127.0.0.1", "mapped, dotted"],
    ["::ffff:7f00:1", "mapped, hex — what URL parsing produces"],
    ["0:0:0:0:0:ffff:7f00:1", "mapped, expanded"],
    ["::ffff:a9fe:a9fe", "mapped — cloud metadata"],
    ["::ffff:a00:1", "mapped — RFC1918"],
    ["::127.0.0.1", "deprecated IPv4-compatible"],
    ["::7f00:1", "IPv4-compatible, as URL parsing rewrites it"],
    ["64:ff9b::7f00:1", "NAT64 well-known prefix"],
  ])("blocks %s (%s)", (addr) => {
    expect(isPrivateAddress(addr)).toBe(true);
  });

  it("still allows a public address written in mapped form", () => {
    expect(isPrivateAddress("::ffff:8.8.8.8")).toBe(false);
  });
});

describe("special ranges the guard used to allow (audit #14)", () => {
  it.each(["224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "ff02::1", "2002:c000:204::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "64:ff9b:1::1"])(
    "blocks %s",
    (addr) => expect(isPrivateAddress(addr)).toBe(true),
  );
  it.each(["8.8.8.8", "223.255.255.254", "2606:4700:4700::1111", "2001:4860:4860::8888"])("still allows %s", (addr) =>
    expect(isPrivateAddress(addr)).toBe(false),
  );
});
