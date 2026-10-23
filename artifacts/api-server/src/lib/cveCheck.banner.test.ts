import { describe, it, expect, beforeAll } from "vitest";
import { setEolCache } from "./eolFetcherData";

process.env["DATABASE_URL"] ||= "postgresql://placeholder:placeholder@127.0.0.1:1/placeholder";

// Live EOL data as the nightly refresh stores it, put in the real in-process cache: PHP 8.2's entry is the
// future-tense early warning, 8.1 is past, and nginx 1.24 is an EOL upstream cycle.
beforeAll(() =>
  setEolCache({
    phpEol: { "8.1": "Reached EOL in December 2025", "8.2": "Reaches EOL in December 2026" },
    nginxEolCycles: new Set(["1.18", "1.24"]),
    apacheEolCycles: new Set(["2.2"]),
    fetchedAt: new Date(),
  }),
);

/** The real check; `now` is the date end-of-life is judged against (the real clock when omitted). */
async function detect(headers: Record<string, string>, now?: Date) {
  const { checkForKnownVulnerabilities } = await import("./cveCheck.js");
  return checkForKnownVulnerabilities("", headers, now ? { now } : {});
}

describe("PHP end-of-life is judged against the date", () => {
  it("a still-supported branch is an INFO early warning, never 'is End-of-Life'", async () => {
    const f = await detect({ "x-powered-by": "PHP/8.2.28" }, new Date("2026-09-30T12:00:00Z"));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("info");
    expect(f[0]!.name).not.toContain("is End-of-Life");
    expect(f[0]!.name).toContain("Reaches End-of-Life in December 2026");
  });
  it("the same entry becomes HIGH once its month has passed", async () => {
    const f = await detect({ "x-powered-by": "PHP/8.2.28" }, new Date("2027-01-15T12:00:00Z"));
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.name).toBe("PHP 8.2.28 is End-of-Life");
  });
  it("a past-EOL upstream PHP is still HIGH", async () => {
    const f = await detect({ "x-powered-by": "PHP/8.1.9" });
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.name).toBe("PHP 8.1.9 is End-of-Life");
  });
});

describe("distro-packaged banners are not judged against upstream", () => {
  it("PHP 8.1.2-1ubuntu2.14 gets no EOL finding", async () =>
    expect(await detect({ "x-powered-by": "PHP/8.1.2-1ubuntu2.14" })).toEqual([]));
  it("nginx/1.24.0 (Ubuntu) gets no HIGH claim and no EOL-cycle claim, only a LOW verify note", async () => {
    const f = await detect({ server: "nginx/1.24.0 (Ubuntu)" });
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("low");
    expect(f[0]!.confidence).toBeLessThanOrEqual(30);
    expect(f[0]!.name).toContain("Verify Distro Package");
    expect(f[0]!.description).toMatch(/backport/);
    expect(f[0]!.description).not.toMatch(/is vulnerable/);
  });
  it("Apache/2.4.58 (Ubuntu) and (Debian) get only the LOW verify note", async () => {
    for (const s of ["Apache/2.4.58 (Ubuntu)", "Apache/2.4.57 (Debian)"]) {
      const f = await detect({ server: s });
      expect(f.map((x) => x.severity)).toEqual(["low"]);
    }
  });
  it("the same upstream versions without a distro marker are still flagged at higher severity", async () => {
    const n = await detect({ server: "nginx/1.24.0" });
    expect(n[0]!.name).toContain("CVE-2026-42533");
    expect(n[0]!.severity).not.toBe("low");
    const a = await detect({ server: "Apache/2.4.60 (Unix)" });
    expect(a[0]!.name).toContain("CVE-2026-34356");
    expect(a[0]!.severity).not.toBe("low");
  });
});

describe("banner-only CVE wording and version ranges", () => {
  it("never says 'is vulnerable' and hedges configuration-dependent flaws", async () => {
    const f = await detect({ server: "Apache/2.4.60" });
    expect(f[0]!.description).not.toMatch(/is vulnerable/);
    expect(f[0]!.description).toMatch(/banner-only/);
    expect(f[0]!.description).toContain("ProxyPassReverseCookie*");
    expect(f[0]!.severity).toBe("medium"); // capped from CVSS 7.5 / high
    expect(f[0]!.confidence).toBeLessThan(50);
  });
  it("Apache 2.4.48 is below the CVE-2021-41773 floor and 2.4.49 is inside it", async () => {
    // The 2.4.68 row wins for both; check the range table directly for the old, narrower row.
    const { matchRange } = await import("./bannerRules.js");
    const { APACHE_VULN_RANGES } = await import("./cve-patterns.js");
    const old = APACHE_VULN_RANGES.filter((r) => r.cve === "CVE-2021-41773");
    expect(matchRange("2.4.48", old)).toBeUndefined();
    expect(matchRange("2.4.49", old)?.cve).toBe("CVE-2021-41773");
    expect(matchRange("2.4.50", old)?.cve).toBe("CVE-2021-41773");
    expect(matchRange("2.4.51", old)).toBeUndefined();
  });
  it("CVE-2023-25690 still covers 2.4.55 (fixed in 2.4.56)", async () => {
    const { matchRange } = await import("./bannerRules.js");
    const { APACHE_VULN_RANGES } = await import("./cve-patterns.js");
    const r = APACHE_VULN_RANGES.filter((x) => x.cve === "CVE-2023-25690");
    expect(matchRange("2.4.55", r)).toBeDefined();
    expect(matchRange("2.4.56", r)).toBeUndefined();
  });
  it("nginx CVE-2019-9511 excludes the already-fixed 1.16.1+/1.17.3+ builds and pre-1.9.5", async () => {
    const { matchRange } = await import("./bannerRules.js");
    const { NGINX_VULN_RANGES } = await import("./cve-patterns.js");
    const r = NGINX_VULN_RANGES.filter((x) => x.cve === "CVE-2019-9511");
    expect(matchRange("1.16.1", r)).toBeUndefined();
    expect(matchRange("1.17.3", r)).toBeUndefined();
    expect(matchRange("1.9.4", r)).toBeUndefined();
    expect(matchRange("1.14.0", r)?.cve).toBe("CVE-2019-9511");
  });
  it("a patched build is still clean", async () => {
    expect(await detect({ server: "nginx/1.30.4" })).toEqual([]);
    expect(await detect({ server: "Apache/2.4.68" })).toEqual([]);
  });
});
