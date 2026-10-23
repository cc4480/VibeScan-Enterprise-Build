import { describe, it, expect } from "vitest";
import { carriesSoftwareVersion } from "./scannerHeaderChecks";

/** www.php.net answers "Server: BunnyCDN-HOU1-893": a CDN edge-node id, not a software version. */
describe("carriesSoftwareVersion", () => {
  it("is false for CDN node ids and bare product names", () => {
    for (const s of ["BunnyCDN-HOU1-893", "cloudflare", "gws", "AmazonS3", "cache-iad-kcgs7200123-IAD", "envoy", "ECS-node2"]) {
      expect(carriesSoftwareVersion(s), s).toBe(false);
    }
  });

  it("is true for real version banners", () => {
    for (const s of ["nginx/1.31.3", "Apache/2.4.41 (Ubuntu)", "Microsoft-IIS/10.0", "Apache/2", "openresty/1.25.3.1", "LiteSpeed/6.1", "Jetty(9.4.51.v20230217)", "Kestrel 2.1"]) {
      expect(carriesSoftwareVersion(s), s).toBe(true);
    }
  });
});

describe("Server Version Disclosure finding", async () => {
  const { headerFindings } = await import("./scannerHeaderChecks");
  const names = (server: string) =>
    headerFindings({ finalUrl: "https://example.com/", rawHeaders: { server }, html: "", isHttps: true }).map((v) => v.name);

  it("is raised for a version banner and not for a CDN node id", () => {
    expect(names("nginx/1.31.3")).toContain("Server Version Disclosure");
    expect(names("BunnyCDN-HOU1-893")).not.toContain("Server Version Disclosure");
  });
});

describe("Referrer-Policy and Permissions-Policy are hardening notes, not exposures", async () => {
  const { headerFindings } = await import("./scannerHeaderChecks");
  const page = (rawHeaders: Record<string, string>) => headerFindings({ finalUrl: "https://example.com/", rawHeaders, html: "", isHttps: true });

  it("a missing Referrer-Policy or Permissions-Policy is Info", () => {
    const found = page({});
    expect(found.find((v) => v.name === "Missing Referrer-Policy Header")?.severity).toBe("info");
    expect(found.find((v) => v.name === "Missing Permissions-Policy Header")?.severity).toBe("info");
  });

  it("clean twin: when both headers are sent, neither is raised", () => {
    const names = page({ "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=()" }).map((v) => v.name);
    expect(names).not.toContain("Missing Referrer-Policy Header");
    expect(names).not.toContain("Missing Permissions-Policy Header");
  });
});
