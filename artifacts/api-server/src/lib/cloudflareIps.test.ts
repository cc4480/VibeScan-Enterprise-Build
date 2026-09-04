import { describe, it, expect, afterEach } from "vitest";
import { isCloudflareIp, _resetCloudflareIps, _rangeCounts } from "./cloudflareIps";

afterEach(() => _resetCloudflareIps());

describe("isCloudflareIp", () => {
  it("ships with the published ranges loaded", () => {
    const { v4, v6 } = _rangeCounts();
    expect(v4).toBeGreaterThanOrEqual(10);
    expect(v6).toBeGreaterThanOrEqual(5);
  });

  it("recognises addresses in Cloudflare's IPv4 ranges", () => {
    for (const ip of [
      "104.21.48.14",   // the address secscan.us resolves to
      "172.67.175.183", // the other edge secscan.us resolves to
      "173.245.48.1",
      "103.21.244.255",
      "141.101.64.0",
      "162.158.0.1",
      "172.64.0.1",
      "131.0.72.3",
    ]) {
      expect(isCloudflareIp(ip), ip).toBe(true);
    }
  });

  it("rejects addresses outside them", () => {
    for (const ip of [
      "8.8.8.8",
      "1.1.1.1",        // Cloudflare's resolver, deliberately NOT an edge range
      "69.46.46.48",    // Railway's origin
      "74.208.236.81",  // the old IONOS host
      "203.0.113.9",
      "104.15.255.255", // one below 104.16.0.0/13
      "131.0.76.0",     // one above 131.0.72.0/22
    ]) {
      expect(isCloudflareIp(ip), ip).toBe(false);
    }
  });

  it("gets the range boundaries right", () => {
    // 104.16.0.0/13 spans 104.16.0.0 – 104.23.255.255.
    expect(isCloudflareIp("104.16.0.0")).toBe(true);
    expect(isCloudflareIp("104.23.255.255")).toBe(true);
    expect(isCloudflareIp("104.15.255.255")).toBe(false);
    // 104.24.0.0/14 picks up where the previous leaves off.
    expect(isCloudflareIp("104.24.0.0")).toBe(true);
    expect(isCloudflareIp("104.28.0.0")).toBe(false);
  });

  it("recognises Cloudflare IPv6 ranges", () => {
    for (const ip of [
      "2606:4700::1",
      "2606:4700:3030::ac43:afb7", // secscan.us over IPv6
      "2400:cb00::1",
      "2a06:98c0::1",
      "[2606:4700::1]",            // bracketed form
    ]) {
      expect(isCloudflareIp(ip), ip).toBe(true);
    }
  });

  it("rejects IPv6 outside them", () => {
    for (const ip of ["2001:4860:4860::8888", "::1", "2607:f1c0:100f:f000::200"]) {
      expect(isCloudflareIp(ip), ip).toBe(false);
    }
  });

  it("judges IPv4-mapped IPv6 by the address it actually names", () => {
    // ::ffff:104.21.48.14 is the same destination written a second way; reading
    // it only as a v6 string would answer "not Cloudflare" and quietly disable
    // the check for any platform that presents addresses in that form.
    expect(isCloudflareIp("::ffff:104.21.48.14")).toBe(true);
    expect(isCloudflareIp("::ffff:8.8.8.8")).toBe(false);
  });

  it("handles a zone index", () => {
    expect(isCloudflareIp("2606:4700::1%eth0")).toBe(true);
  });

  it("returns false for anything that is not an address", () => {
    for (const junk of ["", "   ", "not-an-ip", "999.1.1.1", "104.21.48", "2606:4700::/32"]) {
      expect(isCloudflareIp(junk), JSON.stringify(junk)).toBe(false);
    }
  });
});
