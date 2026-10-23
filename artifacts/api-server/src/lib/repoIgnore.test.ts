import { describe, it, expect } from "vitest";
import { globToRegExp, parseIgnore, applyIgnore, suppressedNotice, IGNORE_FILE } from "./repoIgnore";
import { scanRepository } from "./repoScan";
import type { RepoRef } from "./repoFinding";

const ref: RepoRef = { owner: "acme", repo: "app" };
const finding = (name: string, files: string[], severity: "high" | "low" = "high") => ({ id: name + files.join(), name, severity, category: "Injection", description: "d", evidence: ["Repository: acme/app", ...files.map((f) => `File: ${f}`)].join("\n"), solution: "s", cweId: null, cvssScore: 0 }) as never;

describe("glob matching", () => {
  it.each([
    ["config.py", "src/config.py", true],
    ["config.py", "src/config.pyc", false],
    ["/config.py", "src/config.py", false],
    ["/config.py", "config.py", true],
    ["docs/", "docs/a/b.md", true],
    ["docs/", "mydocs/a.md", false],
    ["src/*.ts", "src/a.ts", true],
    ["src/*.ts", "src/deep/a.ts", false],
    ["src/**/*.ts", "src/deep/er/a.ts", true],
    ["legacy", "legacy/old/x.js", true],
    ["a?.js", "ab.js", true],
  ])("%s vs %s", (glob, path, expected) => expect(globToRegExp(glob).test(path)).toBe(expected));
});

describe("parsing and applying rules", () => {
  const rules = parseIgnore(`# accepted risks\n\nlegacy/\nrule: Compose Publishes a Database Port\nrule: Hardcoded Password @ scripts/seed.*\n`);

  it("reads path, rule and combined rules, skipping comments and blanks", () => {
    expect(rules).toHaveLength(3);
    expect(rules[0]!.path).toBeDefined();
    expect(rules[1]).toMatchObject({ name: "compose publishes a database port" });
    expect(rules[2]!.name && rules[2]!.path).toBeTruthy();
  });

  it("suppresses by path only when every file of the finding matches", () => {
    const { kept, suppressed } = applyIgnore([finding("A", ["legacy/a.js"]), finding("B", ["legacy/a.js", "src/b.js"]), finding("C", ["src/c.js"])], rules);
    expect(suppressed.map((s) => s.finding.name)).toEqual(["A"]);
    expect(kept.map((v) => v.name)).toEqual(["B", "C"]);
  });

  it("suppresses by rule name, and by rule name within a path, but not elsewhere", () => {
    const { suppressed } = applyIgnore([finding("Compose Publishes a Database Port to Every Network Interface", ["compose.yml"]), finding("Hardcoded Password in Source Code", ["scripts/seed.ts"]), finding("Hardcoded Password in Source Code", ["src/auth.ts"])], rules);
    expect(suppressed.map((s) => s.finding.evidence)).toHaveLength(2);
    expect(suppressed.some((s) => s.finding.evidence?.includes("src/auth.ts"))).toBe(false);
  });

  it("never suppresses a coverage note", () => {
    const note = { ...(finding("x", []) as object), category: "Scan Coverage" } as never;
    expect(applyIgnore([note], parseIgnore("rule: x")).suppressed).toEqual([]);
  });
});

describe("the report says what was suppressed", () => {
  it("names the rule and the findings it removed, with counts", () => {
    const rules = parseIgnore("legacy/");
    const { suppressed } = applyIgnore([finding("A", ["legacy/a.js"]), finding("A", ["legacy/b.js"]), finding("B", ["legacy/c.js"])], rules);
    const note = suppressedNotice(suppressed, ref)!;
    expect(note.name).toBe(`3 findings suppressed by ${IGNORE_FILE}`);
    expect(note.category).toBe("Scan Coverage");
    expect(note.evidence).toContain("legacy/  ->  A x2; B");
    expect(suppressedNotice([], ref)).toBeNull();
  });
});

describe("in a scan", () => {
  const source = (files: Record<string, string>) => ({
    via: "public" as const,
    open: async () => ({ ok: true as const, branch: "main", truncated: false, tree: Object.keys(files).map((p) => ({ path: p, size: files[p]!.length })) }),
    read: async (p: string) => files[p] ?? null,
  });
  const env = "STRIPE_SECRET_KEY=Xk9fQ2mLp8Zr4Tv7Nc1Wb6Hs\n";

  it("removes the accepted finding, keeps the others, and says so", async () => {
    const out = await scanRepository(source({ "legacy/.env": env, ".env": env, [IGNORE_FILE]: "legacy/\n" }), ref);
    const names = out.findings.map((v) => `${v.name} | ${v.evidence}`);
    expect(names.some((n) => /legacy\/\.env/.test(n) && !/suppressed/.test(n))).toBe(false);
    expect(out.findings.some((v) => v.name === `2 findings suppressed by ${IGNORE_FILE}` || /suppressed by/.test(v.name))).toBe(true);
    expect(out.findings.some((v) => /^File: \.env$/m.test(v.evidence ?? ""))).toBe(true);
  });

  it("without the file, nothing is suppressed and no note appears", async () => {
    const out = await scanRepository(source({ "legacy/.env": env }), ref);
    expect(out.findings.some((v) => /suppressed by/.test(v.name))).toBe(false);
    expect(out.findings.some((v) => /legacy\/\.env/.test(v.evidence ?? ""))).toBe(true);
  });

  it("is read only from the repository root", async () => {
    const out = await scanRepository(source({ "legacy/.env": env, "sub/.secscanignore": "legacy/\n" }), ref);
    expect(out.findings.some((v) => /suppressed by/.test(v.name))).toBe(false);
  });
});
