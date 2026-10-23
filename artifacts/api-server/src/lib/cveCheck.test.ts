import { describe, it, expect } from "vitest";

// cveCheck.ts pulls in @workspace/db transitively, which throws at module load
// without DATABASE_URL. pg.Pool connects lazily, so a placeholder that resolves
// nowhere is enough — these tests never touch a real database or network call,
// since every technology below is detected via the "local" ecosystem, which
// checkForKnownVulnerabilities() never sends to OSV.dev.
process.env["DATABASE_URL"] ||=
  "postgresql://placeholder:placeholder@127.0.0.1:1/placeholder";

/**
 * NGINX_VULN_RANGES and APACHE_VULN_RANGES had no tests at all before the
 * 2026-09-21 review that added CVE-2026-42533 and CVE-2026-34356 as the new
 * top (highest-threshold) entries in each table. checkLocalVulns() walks the
 * array in order and reports only the first match, so a wrong threshold or a
 * wrong array position silently changes which CVE — or whether any CVE at
 * all — a given version gets flagged with. That has no other symptom.
 */

async function detect(headers: Record<string, string>) {
  const { checkForKnownVulnerabilities } = await import("./cveCheck.js");
  return checkForKnownVulnerabilities("", headers);
}

describe("checkForKnownVulnerabilities — nginx", () => {
  it("flags a pre-1.30.4 nginx with the current top CVE entry", async () => {
    const findings = await detect({ server: "nginx/1.28.0" });
    const hit = findings.find((f) => f.name.includes("Nginx"));
    expect(hit?.name).toContain("CVE-2026-42533");
    // CVSS 8.1 would be high, but the flaw needs a regex map directive a banner cannot show,
    // so a banner-only match is capped at medium (see bannerRules.rangeFinding).
    expect(hit?.severity).toBe("medium");
  });

  it("still flags a very old nginx — with the newest applicable CVE, not a stale one", async () => {
    // The array is ordered by descending threshold specifically so an old
    // install is pointed at the current best-known issue and upgrade target,
    // not whichever CVE happened to be added to the table first.
    const findings = await detect({ server: "nginx/1.14.0" });
    const hit = findings.find((f) => f.name.includes("Nginx"));
    expect(hit?.name).toContain("CVE-2026-42533");
    expect(hit?.name).not.toContain("CVE-2021-23017");
  });

  it("does not flag a current, patched nginx", async () => {
    const findings = await detect({ server: "nginx/1.30.4" });
    expect(findings.find((f) => f.name.includes("Nginx"))).toBeUndefined();
  });
});

describe("checkForKnownVulnerabilities — apache", () => {
  it("flags a pre-2.4.68 Apache with the current top CVE entry", async () => {
    const findings = await detect({ server: "Apache/2.4.60" });
    const hit = findings.find((f) => f.name.includes("Apache"));
    expect(hit?.name).toContain("CVE-2026-34356");
  });

  it("does not flag a current, patched Apache", async () => {
    const findings = await detect({ server: "Apache/2.4.68" });
    expect(findings.find((f) => f.name.includes("Apache"))).toBeUndefined();
  });
});

describe("checkForKnownVulnerabilities — IIS", () => {
  it("still flags IIS 6.x (CVE-2017-7269), unaffected by this review", async () => {
    const findings = await detect({ server: "Microsoft-IIS/6.0" });
    expect(findings.find((f) => f.name.includes("CVE-2017-7269"))).toBeDefined();
  });

  it("does not flag a current IIS major version", async () => {
    const findings = await detect({ server: "Microsoft-IIS/10.0" });
    expect(findings.find((f) => f.name.includes("Microsoft IIS"))).toBeUndefined();
  });
});
