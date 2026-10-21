import { describe, it, expect } from "vitest";
import { isPrivateIp } from "./reconPorts";

describe("isPrivateIp (recon port-scan guard)", () => {
  it("treats CGNAT 100.64/10 as private, which the old list missed", () => {
    expect(isPrivateIp("100.64.0.1")).toBe(true);
    expect(isPrivateIp("100.127.255.254")).toBe(true);
  });

  it("treats benchmarking, multicast and reserved ranges as private", () => {
    expect(isPrivateIp("198.18.0.1")).toBe(true);
    expect(isPrivateIp("224.0.0.1")).toBe(true);
    expect(isPrivateIp("240.0.0.1")).toBe(true);
    expect(isPrivateIp("255.255.255.255")).toBe(true);
  });

  it("keeps the original private ranges and 0.0.0.0", () => {
    expect(isPrivateIp("10.1.2.3")).toBe(true);
    expect(isPrivateIp("172.20.0.1")).toBe(true);
    expect(isPrivateIp("192.168.1.1")).toBe(true);
    expect(isPrivateIp("127.0.0.1")).toBe(true);
    expect(isPrivateIp("169.254.169.254")).toBe(true);
    expect(isPrivateIp("0.0.0.0")).toBe(true);
    expect(isPrivateIp("::1")).toBe(true);
  });

  it("does not block public addresses", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("93.184.216.34")).toBe(false);
    expect(isPrivateIp("100.63.255.255")).toBe(false);
  });
});
