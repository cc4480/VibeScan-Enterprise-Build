import { describe, it, expect } from "vitest";
import { scanRepository } from "./repoScan";
import { githubProbeOutcome } from "./githubSourceProbeOutcome";
import { TestLedger, sourceLines, SOURCE_TEST_NAME } from "./testLedger";
import type { RepoSource } from "./repoSource";

/**
 * The whole path a repository takes into a report: read by the scanner, turned into an outcome, recorded on
 * the ledger. A clean repository used to leave no trace at all (the record said "ran, 0 findings" and
 * nothing about what was read), so there was nothing to show in the report's source-code section.
 */
const ref = { owner: "acme", repo: "taskflow" };

function memorySource(files: Record<string, string>, via: RepoSource["via"] = "public"): RepoSource {
  return {
    via,
    async open() {
      return { ok: true, branch: "main", truncated: false, tree: Object.entries(files).map(([path, c]) => ({ path, size: c.length })) };
    },
    async read(path) { return files[path] ?? null; },
  };
}

async function record(files: Record<string, string>, via: RepoSource["via"] = "public") {
  const ledger = new TestLedger();
  const found = await ledger.trackOutcome(
    "passive", SOURCE_TEST_NAME,
    scanRepository(memorySource(files, via), ref).then((o) => githubProbeOutcome(o, ref)),
  );
  return { rec: ledger.records[0]!, found };
}

describe("a repository scan, as the ledger records it", () => {
  it("keeps what was read and each check's result, for a repository with nothing wrong", async () => {
    const { rec, found } = await record({
      "README.md": "# app",
      "src/index.ts": "export const add = (a: number, b: number) => a + b;\n",
      "supabase/migrations/001.sql": "create table public.notes (id uuid);\nalter table public.notes enable row level security;\n",
    });

    expect(found).toEqual([]);
    expect(rec).toMatchObject({ name: SOURCE_TEST_NAME, status: "ran", findings: 0 });
    expect(rec.source?.repository).toBe("acme/taskflow");
    expect(rec.source?.via).toBe("public");
    expect(rec.source?.read).toBe(3);
    expect(rec.source?.treeFiles).toBe(3);
    expect(rec.source?.checks?.map((c) => c.name)).toEqual([
      "repository secrets",
      "Supabase migrations (RLS and policies)",
      "CI and configuration",
      "dangerous code patterns",
      "dependency vulnerabilities (OSV)",
    ]);
    // The check with nothing to read says so, rather than counting as "passed".
    expect(rec.source?.checks?.find((c) => c.name === "CI and configuration")).toMatchObject({ files: 0, note: "no matching files in the repository" });
    expect(sourceLines([rec]).join("\n")).toContain("Nothing was found in the files that were read.");
  });

  it("keeps the findings count per check, and the names of what was found, for a repository with problems", async () => {
    const { rec, found } = await record(
      {
        ".env.production": "STRIPE_KEY=sk_live_Zk3pQ8vXw2LmN7rT9yBcD4fG\n",
        "supabase/migrations/001_init.sql": "create table public.profiles (id uuid);",
        ".github/workflows/pr.yml": "permissions: write-all\n",
        "src/server.ts": "eval(req.body.x)",
      },
      "github-app",
    );

    expect(found.length).toBeGreaterThan(0);
    expect(rec.status).toBe("ran");
    expect(rec.findings).toBe(found.length);
    expect(rec.source?.via).toBe("github-app");
    const perCheck = Object.fromEntries((rec.source?.checks ?? []).map((c) => [c.name, c.findings]));
    expect(perCheck["repository secrets"]).toBeGreaterThan(0);
    expect(perCheck["Supabase migrations (RLS and policies)"]).toBeGreaterThan(0);
    expect(perCheck["CI and configuration"]).toBeGreaterThan(0);
    expect(perCheck["dangerous code patterns"]).toBeGreaterThan(0);
    expect(rec.found?.length).toBe(found.length);
    expect(sourceLines([rec], found).join("\n")).toContain("through the connected GitHub App");
  });

  it("records a repository GitHub would not show as skipped, still naming it", async () => {
    const ledger = new TestLedger();
    const source: RepoSource = { via: "public", async open() { return { ok: false, status: "not_public_or_missing" }; }, async read() { return null; } };
    await ledger.trackOutcome("passive", SOURCE_TEST_NAME, scanRepository(source, ref).then((o) => githubProbeOutcome(o, ref)));
    expect(ledger.records[0]).toMatchObject({ status: "skipped", source: { repository: "acme/taskflow" } });
    expect(ledger.records[0]?.reason).toMatch(/connect GitHub/);
  });
});
