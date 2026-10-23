import { describe, it, expect } from "vitest";
import { githubProbeOutcome, type GithubScanOutcome } from "./githubSourceProbe";
import { TestLedger } from "./testLedger";

const outcome = (status: GithubScanOutcome["status"]): GithubScanOutcome => ({ findings: [], status, filesRead: 0 });

describe("githubProbeOutcome", () => {
  it("hands back the findings of a repository that was read (scanned or empty)", () => {
    expect(githubProbeOutcome(outcome("scanned"))).toEqual({ findings: [] });
    expect(githubProbeOutcome(outcome("empty"))).toEqual({ findings: [] });
  });

  it("treats a private or missing repository as not tested, and says how to get a private one read", () => {
    const r = githubProbeOutcome(outcome("not_public_or_missing"));
    expect(r.findings).toEqual([]);
    expect(r.notTested).toMatch(/private, or does not exist/);
    expect(r.notTested).toMatch(/connect GitHub/);
    expect(r.notTested).not.toMatch(/only public/);
  });

  it("says something different when a connected GitHub account could not read it", () => {
    const r = githubProbeOutcome({ ...outcome("not_public_or_missing"), via: "github-app" });
    expect(r.notTested).toMatch(/connected GitHub account/);
    expect(r.notTested).toMatch(/no longer be shared/);
  });

  it("keeps what was read and what each check found, when told which repository it was", () => {
    const o: GithubScanOutcome = {
      ...outcome("scanned"),
      filesRead: 12,
      via: "github-app",
      coverage: { treeFiles: 400, chosen: 14, read: 12, bytesRead: 90_000, leftOutByCap: 3, tooLarge: 1, truncatedTree: false, failedReads: 2 },
      checks: [{ name: "repository secrets", files: 4, findings: 0 }, { name: "CI and configuration", files: 0, findings: 0, note: "no matching files in the repository" }],
    };
    const r = githubProbeOutcome(o, { owner: "acme", repo: "app" });
    expect(r.source).toEqual({
      repository: "acme/app", via: "github-app", read: 12, treeFiles: 400, chosen: 14, bytesRead: 90_000,
      leftOut: 3, tooLarge: 1, failedReads: 2, truncatedTree: false, checks: o.checks,
    });
  });

  it("keeps the repository name on a repository that could not be read, so the report can say which", () => {
    expect(githubProbeOutcome(outcome("not_public_or_missing"), { owner: "acme", repo: "app" }).source).toEqual({ repository: "acme/app" });
  });

  it.each(["rate_limited", "unreachable", "blocked", "unreadable"] as const)(
    "still throws for %s, so the ledger records a failure",
    (status) => {
      expect(() => githubProbeOutcome(outcome(status))).toThrow();
    },
  );
});

describe("the ledger's record of a GitHub scan", () => {
  const record = async (status: GithubScanOutcome["status"]) => {
    const ledger = new TestLedger();
    await ledger
      .trackOutcome("passive", "GitHub source code secrets", Promise.resolve(outcome(status)).then(githubProbeOutcome))
      .catch(() => undefined);
    return { records: ledger.records, summary: ledger.summary() };
  };

  it("records a private repository as skipped, not failed", async () => {
    const { records, summary } = await record("not_public_or_missing");
    expect(records[0]).toMatchObject({ name: "GitHub source code secrets", status: "skipped" });
    expect(summary.failed).toBe(0);
    expect(summary.skipped).toBe(1);
  });

  it("still records a rate limit as failed", async () => {
    const { records, summary } = await record("rate_limited");
    expect(records[0]).toMatchObject({ status: "failed" });
    expect(summary.failed).toBe(1);
  });

  it("records a readable repository as ran", async () => {
    const { records } = await record("scanned");
    expect(records[0]).toMatchObject({ status: "ran" });
  });

  it("stores what was read on the record, whether the repository was read or not", async () => {
    const ledger = new TestLedger();
    const ref = { owner: "acme", repo: "app" };
    await ledger.trackOutcome("passive", "GitHub source code secrets", Promise.resolve(githubProbeOutcome({ ...outcome("scanned"), filesRead: 5 }, ref)));
    await ledger.trackOutcome("passive", "second", Promise.resolve(githubProbeOutcome(outcome("not_public_or_missing"), ref)));
    expect(ledger.records[0]).toMatchObject({ status: "ran", source: { repository: "acme/app", read: 5 } });
    expect(ledger.records[1]).toMatchObject({ status: "skipped", source: { repository: "acme/app" } });
  });
});
