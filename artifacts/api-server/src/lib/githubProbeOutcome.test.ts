import { describe, it, expect } from "vitest";
import { githubProbeOutcome, type GithubScanOutcome } from "./githubSourceProbe";
import { TestLedger } from "./testLedger";

const outcome = (status: GithubScanOutcome["status"]): GithubScanOutcome => ({ findings: [], status, filesRead: 0 });

describe("githubProbeOutcome", () => {
  it("hands back the findings of a repository that was read (scanned or empty)", () => {
    expect(githubProbeOutcome(outcome("scanned"))).toEqual({ findings: [] });
    expect(githubProbeOutcome(outcome("empty"))).toEqual({ findings: [] });
  });

  it("treats a private or missing repository as not tested, and says only public ones can be read", () => {
    const r = githubProbeOutcome(outcome("not_public_or_missing"));
    expect(r.findings).toEqual([]);
    expect(r.notTested).toMatch(/private or does not exist/);
    expect(r.notTested).toMatch(/only public repositories/);
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
});
