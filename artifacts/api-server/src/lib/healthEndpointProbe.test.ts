import { describe, it, expect } from "vitest";
import { runtimeKeysIn } from "./healthEndpointProbe";

const JSON_CT = "application/json; charset=utf-8";
const keys = (body: unknown, ct = JSON_CT) => runtimeKeysIn(typeof body === "string" ? body : JSON.stringify(body), ct);

describe("runtimeKeysIn: reports runtime internals", () => {
  it("flags the real-world case that prompted it (seclayer.app, 2026-09-26)", () => {
    const body = {
      status: "Online", version: "public beta", checks: { database: "ok" },
      uptimeSeconds: 45090, instance: "c7e7ccb7", memory: { rssMb: 100 }, timestamp: "2026-09-26T10:04:04.871Z",
    };
    expect(keys(body).sort()).toEqual(["instance", "memory", "rssMb", "uptimeSeconds"].sort());
  });

  it("flags a runtime version and a hostname", () => {
    expect(keys({ status: "ok", nodeVersion: "v20.11.1" })).toEqual(["nodeVersion"]);
    expect(keys({ status: "ok", hostname: "ip-10-0-3-7" })).toEqual(["hostname"]);
  });

  it("finds fields nested inside objects", () => {
    expect(keys({ status: "ok", details: { process: { pid: 42 } } })).toEqual(["pid"]);
  });
});

describe("runtimeKeysIn: stays silent on a correct health check (the clean twins)", () => {
  it("a bare status", () => {
    expect(keys({ status: "ok" })).toEqual([]);
    expect(keys({ status: "healthy", timestamp: "2026-01-01T00:00:00Z" })).toEqual([]);
  });

  it("per-dependency checks that only say ok, even when a check is named 'memory'", () => {
    expect(keys({ status: "ok", checks: { database: "ok", memory: "ok", cache: "up" } })).toEqual([]);
  });

  it("a product version string: not software an attacker can look up", () => {
    expect(keys({ status: "ok", version: "public beta" })).toEqual([]);
    expect(keys({ status: "ok", version: "3f2a9c1" })).toEqual([]);
  });

  it("ambiguous keys that usually mean something harmless", () => {
    expect(keys({ status: "ok", host: "example.com", platform: "web", region: "us-east" })).toEqual([]);
  });

  it("anything that is not JSON: an HTML 200 is a SPA shell or a status page", () => {
    expect(keys("<html><body>uptime: 100%</body></html>", "text/html")).toEqual([]);
    expect(keys('{"uptime": 1}', "text/plain")).toEqual([]);
  });

  it("malformed or empty JSON", () => {
    expect(keys("{not json", JSON_CT)).toEqual([]);
    expect(keys("", JSON_CT)).toEqual([]);
    expect(keys("null", JSON_CT)).toEqual([]);
  });

  it("a status page's uptime percentage presented as a status word", () => {
    expect(keys({ uptime: "ok" })).toEqual([]);
  });
});
