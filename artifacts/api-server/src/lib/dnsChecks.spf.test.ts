import { TXT, dohResponse, noTxt, noMx, hasMx } from "./dnsChecks.testkit";
import { describe, it, expect, vi } from "vitest";
import { checkSpf } from "./dnsChecks.js";
import { countSpfLookups } from "./emailAuthParse.js";

// ─── checkSpf — missing record ───────────────────────────────────────────────

describe("checkSpf — missing record", () => {
  it("returns one high-severity vuln when SPF is missing and MX records exist", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(noTxt())  // TXT query → no SPF
      .mockResolvedValueOnce(hasMx()); // MX query  → sends mail

    const vulns = await checkSpf("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("high");
    expect(vulns[0].name).toMatch(/missing spf/i);
    expect(vulns[0].cweId).toBe("CWE-290");
  });

  it("returns medium severity when SPF is missing and no MX records", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(noTxt())
      .mockResolvedValueOnce(noMx());

    const vulns = await checkSpf("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("medium");
  });

  it("returns empty array on network failure (status -1)", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network error"));
    expect(await checkSpf("example.com")).toEqual([]);
  });
});

// ─── checkSpf — dangerous configurations ─────────────────────────────────────

describe("checkSpf — dangerous configurations", () => {
  it("flags +all (permits any sender) as critical", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=spf1 include:_spf.google.com +all" }]),
    );
    const vulns = await checkSpf("example.com");
    expect(vulns.some((v) => v.severity === "critical" && v.name.includes("+all"))).toBe(true);
  });

  it("flags ?all (neutral — no enforcement) as medium", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=spf1 include:_spf.google.com ?all" }]),
    );
    const vulns = await checkSpf("example.com");
    expect(vulns.some((v) => v.severity === "medium" && v.name.includes("?all"))).toBe(true);
  });

  it("flags SPF that exceeds 10 DNS lookups as low", async () => {
    const manyIncludes =
      "v=spf1 " +
      Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(" ") +
      " -all";
    vi.mocked(fetch).mockResolvedValueOnce(dohResponse([{ data: manyIncludes }]));
    const vulns = await checkSpf("example.com");
    const v = vulns.find((x) => /lookup limit/i.test(x.name));
    expect(v).toBeDefined();
    expect(v!.evidence).toMatch(/: 11/);
  });

  it("does not say the limit is exceeded at 9 lookups", async () => {
    const nine = "v=spf1 " + Array.from({ length: 9 }, (_, i) => `include:s${i}.example.net`).join(" ") + " -all";
    vi.mocked(fetch).mockResolvedValueOnce(dohResponse([{ data: nine }]));
    expect((await checkSpf("example.com")).some((v) => /lookup limit/i.test(v.name))).toBe(false);
  });

  it("does not count 'a:' inside ip6 ranges (a flattened record with 1 include)", async () => {
    const flattened =
      "v=spf1 include:_spf.example.net " +
      Array.from({ length: 8 }, (_, i) => `ip6:2a03:2880:f10${i}a:83::/64`).join(" ") +
      " ip4:192.0.2.0/24 -all";
    expect(countSpfLookups(flattened)).toBe(1);
    vi.mocked(fetch).mockResolvedValueOnce(dohResponse([{ data: flattened }]));
    expect(await checkSpf("example.com")).toEqual([]);
  });

  it("returns no vulns for a well-formed SPF record with -all", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=spf1 include:_spf.google.com -all" }]),
    );
    expect(await checkSpf("example.com")).toHaveLength(0);
  });

  it("returns no vulns for ~all (soft fail — acceptable)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=spf1 include:_spf.google.com ~all" }]),
    );
    expect(await checkSpf("example.com")).toHaveLength(0);
  });
});
