import { describe, it, expect } from "vitest";
import { networkOf, networkKey, ACCOUNTS_PER_NETWORK, SIGNUP_WINDOW_DAYS } from "./signupNetwork";

describe("networkOf — what counts as one network", () => {
  it("an IPv4 address is its own network", () => {
    expect(networkOf("198.51.100.7")).toBe("198.51.100.7");
  });

  it("IPv4-mapped IPv6 is the IPv4 it carries", () => {
    expect(networkOf("::ffff:198.51.100.7")).toBe("198.51.100.7");
  });

  it("every address in an IPv6 /64 is the same network, however it is written", () => {
    const a = networkOf("2001:db8:1:2::1");
    expect(networkOf("2001:0db8:0001:0002:ffff:ffff:ffff:ffff")).toBe(a);
    expect(networkOf("2001:DB8:1:2:aaaa::")).toBe(a);
    expect(networkOf("[2001:db8:1:2::5]")).toBe(a);
    expect(networkOf("2001:db8:1:2::5%eth0")).toBe(a);
  });

  it("a different /64 is a different network", () => {
    expect(networkOf("2001:db8:1:3::1")).not.toBe(networkOf("2001:db8:1:2::1"));
  });

  it("an unparseable value still lands in a bucket instead of escaping the cap", () => {
    expect(networkOf("not-an-ip")).toBe("raw:not-an-ip");
  });
});

describe("networkKey — what is stored", () => {
  it("is a hash, never the address", () => {
    const k = networkKey("198.51.100.7");
    expect(k).toMatch(/^[0-9a-f]{64}$/);
    expect(k).not.toContain("198.51.100.7");
  });

  it("is the same for every address in one network", () => {
    expect(networkKey("2001:db8:1:2::1")).toBe(networkKey("2001:db8:1:2:9::9"));
    expect(networkKey("198.51.100.7")).not.toBe(networkKey("198.51.100.8"));
  });
});

describe("the cap decided on 2026-09-25", () => {
  it("is 2 new accounts per network per 30 days", () => {
    expect(ACCOUNTS_PER_NETWORK).toBe(2);
    expect(SIGNUP_WINDOW_DAYS).toBe(30);
  });
});
