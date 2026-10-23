import { useDohStub, txt, MX } from "./dohStub.testkit";
import { describe, it, expect } from "vitest";
import { checkSpf } from "./dnsChecks.js";
import { countSpfLookups } from "./emailAuthParse.js";

// The resolver is a real DNS-over-HTTPS server on loopback (lib/dohStub.testkit.ts); the zone is set in each test.
const doh = await useDohStub();
const publishSpf = (record: string) => doh.set("example.com", "TXT", txt(record));

// ─── checkSpf — missing record ───────────────────────────────────────────────

describe("checkSpf — missing record", () => {
  it("returns one high-severity vuln when SPF is missing and MX records exist", async () => {
    doh.set("example.com", "MX", [{ data: "10 mail.example.com.", type: MX }]);

    const vulns = await checkSpf("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("high");
    expect(vulns[0].name).toMatch(/missing spf/i);
    expect(vulns[0].cweId).toBe("CWE-290");
  });

  it("returns medium severity when SPF is missing and no MX records", async () => {
    const vulns = await checkSpf("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("medium");
  });

  it("returns empty array when the resolver cannot be reached (status -1)", async () => {
    doh.down = true;
    expect(await checkSpf("example.com")).toEqual([]);
  });
});

// ─── checkSpf — dangerous configurations ─────────────────────────────────────

describe("checkSpf — dangerous configurations", () => {
  it("flags +all (permits any sender) as critical", async () => {
    publishSpf("v=spf1 include:_spf.google.com +all");
    const vulns = await checkSpf("example.com");
    expect(vulns.some((v) => v.severity === "critical" && v.name.includes("+all"))).toBe(true);
  });

  it("flags ?all (neutral — no enforcement) as medium", async () => {
    publishSpf("v=spf1 include:_spf.google.com ?all");
    const vulns = await checkSpf("example.com");
    expect(vulns.some((v) => v.severity === "medium" && v.name.includes("?all"))).toBe(true);
  });

  it("flags SPF that exceeds 10 DNS lookups as low", async () => {
    const manyIncludes =
      "v=spf1 " +
      Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(" ") +
      " -all";
    publishSpf(manyIncludes);
    const vulns = await checkSpf("example.com");
    const v = vulns.find((x) => /lookup limit/i.test(x.name));
    expect(v).toBeDefined();
    expect(v!.evidence).toMatch(/: 11/);
  });

  it("does not say the limit is exceeded at 9 lookups", async () => {
    const nine = "v=spf1 " + Array.from({ length: 9 }, (_, i) => `include:s${i}.example.net`).join(" ") + " -all";
    publishSpf(nine);
    expect((await checkSpf("example.com")).some((v) => /lookup limit/i.test(v.name))).toBe(false);
  });

  it("does not count 'a:' inside ip6 ranges (a flattened record with 1 include)", async () => {
    const flattened =
      "v=spf1 include:_spf.example.net " +
      Array.from({ length: 8 }, (_, i) => `ip6:2a03:2880:f10${i}a:83::/64`).join(" ") +
      " ip4:192.0.2.0/24 -all";
    expect(countSpfLookups(flattened)).toBe(1);
    publishSpf(flattened);
    expect(await checkSpf("example.com")).toEqual([]);
  });

  it("returns no vulns for a well-formed SPF record with -all", async () => {
    publishSpf("v=spf1 include:_spf.google.com -all");
    expect(await checkSpf("example.com")).toHaveLength(0);
  });

  it("returns no vulns for ~all (soft fail — acceptable)", async () => {
    publishSpf("v=spf1 include:_spf.google.com ~all");
    expect(await checkSpf("example.com")).toHaveLength(0);
  });
});
