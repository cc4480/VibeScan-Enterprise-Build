import { dohResponse, noTxt } from "./dnsChecks.testkit";
import { describe, it, expect, vi } from "vitest";
import { checkDmarc, checkDkim, COMMON_DKIM_SELECTORS } from "./dnsChecks.js";

// ─── checkDmarc — missing record ─────────────────────────────────────────────

describe("checkDmarc — missing record", () => {
  it("returns one high-severity vuln when DMARC record is missing", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(noTxt());
    const vulns = await checkDmarc("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("high");
    expect(vulns[0].name).toMatch(/missing dmarc/i);
  });

  it("returns empty array on network failure", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network error"));
    expect(await checkDmarc("example.com")).toEqual([]);
  });
});

// ─── checkDmarc — policy enforcement ─────────────────────────────────────────

describe("checkDmarc — policy enforcement", () => {
  it("flags p=none (monitoring only) as medium", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=DMARC1; p=none; rua=mailto:dmarc@example.com" }]),
    );
    const vulns = await checkDmarc("example.com");
    expect(vulns.some((v) => v.severity === "medium" && /none/i.test(v.name))).toBe(true);
  });

  it("flags missing rua= as info", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=DMARC1; p=quarantine" }]),
    );
    const vulns = await checkDmarc("example.com");
    expect(vulns.some((v) => v.severity === "info" && /rua/i.test(v.name))).toBe(true);
  });

  it("returns no vulns for a fully enforced DMARC record with rua=", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com" }]),
    );
    expect(await checkDmarc("example.com")).toHaveLength(0);
  });

  it("flags p=none AND missing rua= as two separate findings", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=DMARC1; p=none" }]),
    );
    const vulns = await checkDmarc("example.com");
    expect(vulns.length).toBeGreaterThanOrEqual(2);
  });
});

describe("checkDkim", () => {
  it("carries the resend selector", () => {
    // Regression: secscan.us's own DKIM record lives at resend._domainkey and
    // was missing from this list, which would have made this checker report
    // "No DKIM" against a domain actively sending signed, delivering mail.
    expect(COMMON_DKIM_SELECTORS).toContain("resend");
  });

  it("finds a record under the resend selector and reports nothing", async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("resend._domainkey")) {
        return dohResponse([{ data: '"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB..."' }]);
      }
      return noTxt();
    });

    const vulns = await checkDkim("secscan.us");
    expect(vulns).toEqual([]);
  });

  it("still reports when every selector, including resend, comes back empty", async () => {
    vi.mocked(fetch).mockImplementation(async () => noTxt());

    const vulns = await checkDkim("example.com");
    expect(vulns.length).toBe(1);
    expect(vulns[0]!.name).toMatch(/No DKIM/i);
  });
});
