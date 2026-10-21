/**
 * The catalog is the public claim about what a scan checks, so it is verified
 * against the code that does the checking rather than trusted.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { moduleSource } from "../testing/moduleSource";
import { CATALOG, REPO_TOTAL_CHECKS, TOTAL_CHECKS, WEBSITE_TOTAL_CHECKS, catalogFor } from "./checkCatalog";

const LIB = __dirname;
const src = (file: string) => moduleSource(LIB, file);

/**
 * The source with its comments removed and its string literals kept. A check that is named
 * only in a comment is not emitted, so it must not satisfy the catalog. This is a small
 * scanner, not a parser: it does not understand regex literals, so a line with a quote inside
 * a regex can throw it off. That fails safe, since the needle then goes missing and the test fails.
 */
function liveCode(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    const d = text[i + 1];
    if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < text.length && text[j] !== c) j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === "/" && d === "/") {
      const end = text.indexOf("\n", i);
      i = end < 0 ? text.length : end;
    } else if (c === "/" && d === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end < 0 ? text.length : end + 2;
      out += " ";
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

describe("the catalog matches the scanner's source", () => {
  it("carries the number of checks the site claims, itemised", () => {
    // Deliberate: changing the count is a public-claim change, so it must be edited here too.
    // 140 → 143: GitHub source-code secret scanning, LLM prompt-injection extraction,
    // and the active race-condition probe. 143 → 144: the TLS grade note that says why a grade
    // is below A. 144 → 156: the scanner's own TLS configuration check, which replaces the SSL Labs
    // grade as the default (the two SSL Labs checks stay listed; they run only with SSLLABS_ENABLED).
    // The website scan's catalog stands at 158 (WEBSITE_TOTAL_CHECKS). The repository scan's own checks
    // (secrets, Supabase migrations, CI and configuration, code patterns, dependencies) add 56
    // (REPO_TOTAL_CHECKS), counted from checkCatalogRepo.ts, which the catalog did not list before.
    // So TOTAL_CHECKS = 158 + 56 = 214.
    expect(WEBSITE_TOTAL_CHECKS).toBe(158);
    expect(REPO_TOTAL_CHECKS).toBe(56);
    expect(TOTAL_CHECKS).toBe(214);
    expect(CATALOG.flatMap((t) => t.checks)).toHaveLength(TOTAL_CHECKS);
  });

  it("finds every check's name as a string literal in live code, in the file that raises it", () => {
    // Comments are stripped first, so a check that survives only in a comment (or in a
    // removed-check note) fails here. What this still cannot prove is that the code holding the
    // literal is ever called: that is dead-code detection, which needs the scanner's runtime
    // ledger, not a text search. The finding-level tests in the scanner's own suites cover that.
    const missing: string[] = [];
    const code = new Map<string, string>();
    const liveFor = (file: string) => {
      if (!code.has(file)) code.set(file, liveCode(src(file)));
      return code.get(file)!;
    };
    for (const t of CATALOG) {
      for (const c of t.checks) {
        const file = c.file ?? t.file;
        const needle = c.needle ?? c.name;
        // Live code includes the text of string and template literals, so this matches a name
        // the scanner builds (`${what} Rules Let Anyone Write`) as well as a fixed one.
        if (!liveFor(file).includes(needle)) missing.push(`${t.test} → ${c.name} (needle "${needle}" not in live code of ${file})`);
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
  // A family is declared either as { family: "…" } or through outcome("…", …), the form for
  // probes that can say they had nothing to test.
  const families = [...scanner.matchAll(/(?:family:\s*|outcome\()"([^"]+)"/g)].map((m) => m[1]).filter((n) => !n.startsWith("HTTP probes"));
  const httpProbes = [...probes.matchAll(/\["([^"]+)",\s*(?:check|run)\w+\(/g)].map((m) => m[1]);
  const named = [
    "response headers and cookies",
    "site crawl",
    "API endpoint testing (auth, injection, IDOR, mass assignment)",
    "SSRF (out-of-band callback)",
    "cross-account access control (IDOR)",
    "TLS configuration check",
    "SSL Labs TLS grade",
    "port scan",
    "LLM prompt injection (system prompt extraction)",
    "race condition (one-time action)",
    "business logic: checkout price",
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
    // The repository scan records its groups as steps of its own (repoScan.ts), not through the ledger families.
    const repoScan = src("repoScan.ts");
    const repoSteps = [...repoScan.matchAll(/(?:record|run)\("([^"]+)"/g)].map((m) => m[1]!);
    const repoDeps = [...repoScan.matchAll(/name: "(dependency vulnerabilities \(OSV\))"/g)].map((m) => m[1]!);
    const recorded = [...families, ...httpProbes, ...named, ...repoSteps, ...repoDeps];
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
    expect(catalogFor("TLS configuration check (TLS 1.3 negotiated, certificate valid for 80 more days)")?.test).toBe("TLS configuration check");
    expect(catalogFor("TLS configuration check")?.test).toBe("TLS configuration check");
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
