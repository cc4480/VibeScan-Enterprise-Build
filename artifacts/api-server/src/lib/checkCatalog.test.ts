/**
 * The catalog is the public claim about what a scan checks, so it is verified
 * against the code that does the checking rather than trusted.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { moduleSource } from "../testing/moduleSource";
import { CATALOG, TOTAL_CHECKS, catalogFor } from "./checkCatalog";

const LIB = __dirname;
const src = (file: string) => moduleSource(LIB, file);

describe("the catalog matches the scanner's source", () => {
  it("carries the number of checks the site claims, itemised", () => {
    // Deliberate: changing the count is a public-claim change, so it must be edited here too.
    // 140 → 143: GitHub source-code secret scanning, LLM prompt-injection extraction,
    // and the active race-condition probe.
    expect(TOTAL_CHECKS).toBe(143);
    expect(CATALOG.flatMap((t) => t.checks)).toHaveLength(TOTAL_CHECKS);
  });

  it("finds every check's name in the file that raises it", () => {
    const missing: string[] = [];
    for (const t of CATALOG) {
      for (const c of t.checks) {
        const file = c.file ?? t.file;
        const needle = c.needle ?? c.name;
        if (!src(file).includes(needle)) missing.push(`${t.test} → ${c.name} (needle "${needle}" not in ${file})`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("lists no check twice within a test, and no test twice", () => {
    expect(new Set(CATALOG.map((t) => t.test)).size).toBe(CATALOG.length);
    for (const t of CATALOG) expect(new Set(t.checks.map((c) => c.name)).size, t.test).toBe(t.checks.length);
  });
});

/** Ledger tests that are steps, not detections: they raise no findings of their own. */
const NO_CHECKS = ["API surface discovery", "DNS records", "subdomain enumeration"];

describe("every test the scanner records is accounted for", () => {
  const scanner = src("scanner.ts");
  const probes = src("probes.ts");
  // Names as the ledger records them, read from the source that records them.
  // The "HTTP probes (…)" family is a bundle the scanner does not record itself: its
  // thirteen inner tests are recorded one by one (httpProbes below).
  const families = [...scanner.matchAll(/family:\s*"([^"]+)"/g)].map((m) => m[1]).filter((n) => !n.startsWith("HTTP probes"));
  const httpProbes = [...probes.matchAll(/\["([^"]+)",\s*(?:check|run)\w+\(/g)].map((m) => m[1]);
  const named = [
    "response headers and cookies",
    "site crawl",
    "API endpoint testing (auth, injection, IDOR, mass assignment)",
    "SSRF (out-of-band callback)",
    "cross-account access control (IDOR)",
    "SSL Labs TLS grade",
    "port scan",
    "LLM prompt injection (system prompt extraction)",
    "race condition (one-time action)",
  ];

  it("finds the ledger names it is checking against", () => {
    expect(families.length).toBeGreaterThanOrEqual(17);
    expect(httpProbes.length).toBe(13);
  });

  it("maps every one to a catalog test, or lists it as a step with no checks", () => {
    const unmapped = [...families, ...httpProbes, ...named].filter(
      (n) => !catalogFor(n) && !NO_CHECKS.some((s) => n.startsWith(s)),
    );
    expect(unmapped).toEqual([]);
  });

  it("has no catalog test that no scan ever records", () => {
    const recorded = [...families, ...httpProbes, ...named];
    const orphans = CATALOG.filter((t) => !recorded.some((n) => catalogFor(n)?.test === t.test)).map((t) => t.test);
    expect(orphans).toEqual([]);
  });

  it("records the header and cookie test in the scanner itself", () => {
    expect(scanner).toContain('name: "response headers and cookies"');
  });
});

describe("catalogFor", () => {
  it("matches a test whose name carries a count, and prefers the longer key", () => {
    expect(catalogFor("site crawl (14 inner pages)")?.test).toBe("site crawl");
    expect(catalogFor("SSL Labs TLS grade (A+)")?.test).toBe("SSL Labs TLS grade");
    expect(catalogFor("Supabase RLS")?.test).toBe("Supabase RLS");
    expect(catalogFor("Supabase RLS and Firebase rules")?.test).toBe("Supabase RLS and Firebase rules");
  });

  it("returns nothing for a step with no findings of its own", () => {
    expect(catalogFor("DNS records (12)")).toBeNull();
    expect(catalogFor("subdomain enumeration (2 found)")).toBeNull();
    expect(catalogFor("API surface discovery (9 endpoints)")).toBeNull();
  });
});

describe("every category the catalog uses has a colour", () => {
  // The palette lives in the web app; reading its source keeps the two from drifting apart.
  const palette = readFileSync(join(LIB, "../../../vibescan/src/lib/category-colors.ts"), "utf8");

  it("finds each test's and check's category in the palette", () => {
    const used = new Set<string>();
    for (const t of CATALOG) {
      used.add(t.category);
      for (const c of t.checks) if (c.category) used.add(c.category);
    }
    const missing = [...used].filter((c) => !palette.includes(`"${c}":`));
    expect(missing).toEqual([]);
  });
});
