import { describe, it, expect, vi, beforeEach } from "vitest";

/** The job for a repository with no website: what it saves, and what it does when the repository cannot be read. */
const calls = { persisted: [] as Array<Record<string, any>>, failedUpdates: [] as Array<Record<string, any>>, refunds: 0 };
let outcome: any;

vi.mock("@workspace/db", () => ({
  db: { update: () => ({ set: (v: Record<string, any>) => { calls.failedUpdates.push(v); return { where: () => Promise.resolve() }; } }) },
  scansTable: { id: "id" },
  reportsTable: {},
}));
vi.mock("./workerPersist", () => ({
  persistReport: async (input: Record<string, any>) => { calls.persisted.push(input); },
  refundIfPaid: async () => { calls.refunds += 1; },
}));
vi.mock("./repoScan", () => ({ scanRepository: async () => outcome }));
vi.mock("./repoSource", () => ({ githubInstallationSource: () => ({}), publicGithubSource: () => ({}) }));

import { processRepoOnlyJob } from "./workerRepoJob";

const log = { info() {}, warn() {}, error() {}, child() { return this; } } as any;
const base = { scanId: "s1", userId: "u1", targetUrl: "https://github.com/acme/app", tier: "deep", githubAccessToken: undefined, log };

beforeEach(() => { calls.persisted = []; calls.failedUpdates = []; calls.refunds = 0; });

describe("processRepoOnlyJob", () => {
  it("saves a report with the source record and no site data when the repository was read", async () => {
    outcome = {
      status: "scanned", findings: [], filesRead: 3, via: "public",
      coverage: { treeFiles: 4, chosen: 3, read: 3, bytesRead: 900, leftOutByCap: 0, tooLarge: 0, truncatedTree: false, failedReads: 0, byCheck: {}, notRead: { binary: 1, vendored: 0 } },
      checks: [{ name: "repository secrets", files: 3, findings: 0 }],
    };
    await processRepoOnlyJob(base);
    expect(calls.persisted).toHaveLength(1);
    const saved = calls.persisted[0]!;
    expect(saved.reportData.targetUrl).toBe("https://github.com/acme/app");
    expect(saved.reportData.certExpiry).toBeNull();
    expect(saved.reportData.summary.executiveSummary).toMatch(/Source code scan of acme\/app/);
    expect(saved.reportData.summary.executiveSummary).toMatch(/did not test any running site/);
    expect(saved.tests[0]).toMatchObject({ status: "ran", source: { repository: "acme/app", read: 3 } });
    expect(calls.refunds).toBe(0);
  });

  it("fails the scan and gives the payment back when the repository could not be read", async () => {
    outcome = { status: "not_public_or_missing", findings: [], filesRead: 0 };
    await processRepoOnlyJob(base);
    expect(calls.persisted).toHaveLength(0);
    expect(calls.failedUpdates[0]).toMatchObject({ status: "failed" });
    expect(String(calls.failedUpdates[0]!.error)).toMatch(/not charged/i);
    expect(calls.refunds).toBe(1);
  });

  it("fails and refunds for an address that is not a repository", async () => {
    await processRepoOnlyJob({ ...base, targetUrl: "https://example.com" });
    expect(calls.persisted).toHaveLength(0);
    expect(calls.refunds).toBe(1);
  });
});
