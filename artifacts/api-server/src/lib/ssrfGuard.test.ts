import { describe, it, expect, vi, afterEach } from "vitest";
import {
  isPrivateAddress,
  isHostnameSafeSync,
  checkHostname,
  checkScanTarget,
} from "./ssrfGuard";

// `dns.resolve` is the only I/O in the module — stub it so these stay unit tests.
vi.mock("node:dns/promises", () => ({
  resolve: vi.fn(),
}));
const dns = await import("node:dns/promises");

afterEach(() => {
  vi.mocked(dns.resolve).mockReset();
});

describe("isPrivateAddress", () => {
  it.each([
    "127.0.0.1",
    "127.1.1.1",
    "10.0.0.5",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // AWS/Azure IMDS
    "100.64.0.1", // CGNAT
    "0.0.0.0",
    "::1",
    "fd00::1",
    "fe80::1",
  ])("blocks %s", (ip) => {
    expect(isPrivateAddress(ip)).toBe(true);
  });

  it.each(["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.15.0.1", "172.32.0.1", "2606:4700::1"])(
    "allows public %s",
    (ip) => {
      expect(isPrivateAddress(ip)).toBe(false);
    },
  );

  it("unwraps IPv4-mapped IPv6 before testing", () => {
    expect(isPrivateAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isPrivateAddress("::ffff:169.254.169.254")).toBe(true);
    expect(isPrivateAddress("::ffff:8.8.8.8")).toBe(false);
  });
});

describe("isHostnameSafeSync", () => {
  it("blocks known internal names", () => {
    expect(isHostnameSafeSync("localhost")).toBe(false);
    expect(isHostnameSafeSync("metadata.google.internal")).toBe(false);
    expect(isHostnameSafeSync("db.internal")).toBe(false);
    expect(isHostnameSafeSync("printer.local")).toBe(false);
  });

  it("blocks literal private IPs without a DNS lookup", () => {
    expect(isHostnameSafeSync("127.0.0.1")).toBe(false);
    expect(isHostnameSafeSync("169.254.169.254")).toBe(false);
  });

  it("allows ordinary public hostnames", () => {
    expect(isHostnameSafeSync("example.com")).toBe(true);
  });

  it("rejects an empty hostname", () => {
    expect(isHostnameSafeSync("")).toBe(false);
  });
});

describe("checkHostname", () => {
  it("blocks a public name that resolves somewhere internal", async () => {
    vi.mocked(dns.resolve).mockResolvedValue(["127.0.0.1"] as never);
    const r = await checkHostname("evil.example.com");
    expect(r.safe).toBe(false);
  });

  it("blocks when any one of several records is internal", async () => {
    vi.mocked(dns.resolve).mockResolvedValue(["93.184.216.34", "10.0.0.1"] as never);
    expect((await checkHostname("mixed.example.com")).safe).toBe(false);
  });

  it("allows a fully public resolution", async () => {
    vi.mocked(dns.resolve).mockResolvedValue(["93.184.216.34"] as never);
    expect((await checkHostname("example.com")).safe).toBe(true);
  });

  it("fails closed when DNS rejects", async () => {
    vi.mocked(dns.resolve).mockRejectedValue(new Error("ENOTFOUND"));
    expect((await checkHostname("nope.example.com")).safe).toBe(false);
  });

  it("fails closed on an empty record set", async () => {
    vi.mocked(dns.resolve).mockResolvedValue([] as never);
    expect((await checkHostname("empty.example.com")).safe).toBe(false);
  });

  it("normalises case and a trailing root dot", async () => {
    expect((await checkHostname("LOCALHOST")).safe).toBe(false);
    expect((await checkHostname("localhost.")).safe).toBe(false);
  });

  it("recognises a bracketed IPv6 literal as written in a URL", async () => {
    expect((await checkHostname("[::1]")).safe).toBe(false);
    expect(dns.resolve).not.toHaveBeenCalled();
  });

  it("skips DNS for a literal public IP", async () => {
    expect((await checkHostname("8.8.8.8")).safe).toBe(true);
    expect(dns.resolve).not.toHaveBeenCalled();
  });
});

describe("checkScanTarget", () => {
  it("rejects non-http protocols", async () => {
    for (const u of ["file:///etc/passwd", "gopher://x/", "ftp://example.com/"]) {
      const r = await checkScanTarget(u);
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/http/i);
    }
  });

  it("rejects a malformed URL", async () => {
    expect((await checkScanTarget("not a url")).safe).toBe(false);
  });

  it("rejects loopback and metadata targets", async () => {
    expect((await checkScanTarget("http://127.0.0.1:9999/")).safe).toBe(false);
    expect((await checkScanTarget("http://169.254.169.254/latest/meta-data/")).safe).toBe(false);
    expect((await checkScanTarget("http://localhost:8080/")).safe).toBe(false);
  });

  it("allows a normal public target over http and https", async () => {
    vi.mocked(dns.resolve).mockResolvedValue(["93.184.216.34"] as never);
    expect((await checkScanTarget("https://example.com/")).safe).toBe(true);
    expect((await checkScanTarget("http://example.com/")).safe).toBe(true);
  });

  it("gives a reason that does not echo internal detail", async () => {
    const r = await checkScanTarget("http://127.0.0.1/");
    expect(r.reason).toBeDefined();
    expect(r.reason).not.toContain("127.0.0.1");
  });
});
