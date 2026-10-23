/**
 * The job for a repository with no website, against a REAL Postgres (BILLING_TEST_DATABASE_URL) and the real GitHub
 * API: what it saves, and what it does when the repository cannot be read.
 *
 * It reads octocat/Hello-World, a small public repository GitHub keeps for exactly this kind of demonstration. The
 * tests that need GitHub skip, rather than fail, when GitHub cannot be reached or is rate limiting this address.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pino from "pino";
import { dbSuiteOf, useRealDb, openDb, makeUser, uniqueEmail } from "./realDb.testkit";
import { buildFallbackAnalysis } from "./fixPromptFallback";
import { detectAgentEnvironment } from "./deepseek";
import { SOURCE_TEST_NAME } from "./testLedger";

useRealDb();

const log = pino({ level: "silent" }) as never;
const REPO = "https://github.com/octocat/Hello-World";

dbSuiteOf(describe)("processRepoOnlyJob (real Postgres, real GitHub)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let job: typeof import("./workerRepoJob");
  let credits: typeof import("./credits");
  let userId: string;
  let githubUp = false;

  /** A running repository-only scan that was paid for with a credit. */
  async function scan(targetUrl: string) {
    const [s] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId, userEmail: uniqueEmail("repojob"), targetUrl, tier: "deep", status: "scanning", paidWith: "credit" })
      .returning({ id: dbMod.scansTable.id });
    return s!.id;
  }
  const scanRow = async (id: string) => (await dbMod.db.select().from(dbMod.scansTable).where(eq(dbMod.scansTable.id, id)))[0]!;
  const reportOf = async (id: string) => (await dbMod.db.select().from(dbMod.reportsTable).where(eq(dbMod.reportsTable.scanId, id)))[0];
  const base = (scanId: string, targetUrl: string) => ({ scanId, userId, targetUrl, tier: "deep", githubAccessToken: undefined, log });

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    job = await import("./workerRepoJob");
    credits = await import("./credits");
    userId = await makeUser(dbMod, "repojob-owner");
    await dbMod.db.insert(dbMod.creditsTable).values({ userId, balance: 0 });
    try {
      const res = await fetch("https://api.github.com/repos/octocat/Hello-World", { headers: { "User-Agent": "SecScan-tests" }, signal: AbortSignal.timeout(8_000) });
      githubUp = res.ok;
    } catch {
      githubUp = false;
    }
  }, 60_000);

  afterAll(async () => {
    const { eq: eqq } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.reportsTable).where(eqq(dbMod.reportsTable.userId, userId));
    await dbMod.db.delete(dbMod.scansTable).where(eqq(dbMod.scansTable.userId, userId));
    await dbMod.db.delete(dbMod.creditsTable).where(eqq(dbMod.creditsTable.userId, userId));
    await dbMod.db.delete(dbMod.usersTable).where(eqq(dbMod.usersTable.id, userId));
    await dbMod?.pool?.end?.();
  });

  it("saves a report with the source record and no site data when the repository was read", async (ctx) => {
    if (!githubUp) ctx.skip();
    const id = await scan(REPO);
    const before = await credits.creditBalance(userId);
    await job.processRepoOnlyJob(base(id, REPO));

    const report = await reportOf(id);
    expect(report).toBeDefined();
    const data = report!.data as any;
    expect(data.targetUrl).toBe(REPO);
    expect(data.certExpiry).toBeNull();
    expect(data.summary.executiveSummary).toMatch(/Source code scan of octocat\/Hello-World/);
    expect(data.summary.executiveSummary).toMatch(/did not test any running site/);
    // The saved report keeps only the one record.
    expect(data.tests.map((t: any) => t.name)).toEqual([SOURCE_TEST_NAME]);
    expect(data.tests[0]).toMatchObject({ status: "ran", source: { repository: "octocat/Hello-World" } });
    expect(data.tests[0].source.read).toBeGreaterThan(0);
    expect((await scanRow(id)).status).toBe("complete");
    expect(await credits.creditBalance(userId)).toBe(before); // read, so charged
  });

  it("shows each step on the progress page as it happens, and keeps them out of the saved report", async (ctx) => {
    if (!githubUp) ctx.skip();
    const id = await scan(REPO);
    await job.processRepoOnlyJob(base(id, REPO));
    const live = ((await scanRow(id)).liveTests ?? []) as Array<{ name: string; status: string; detail?: string }>;
    const names = live.map((r) => r.name);
    expect(names[0]).toBe("Listing the repository's files");
    expect(names.some((n) => /^Reading files \(\d+ of \d+\)$/.test(n))).toBe(true);
    expect(names.some((n) => n.startsWith("Check: "))).toBe(true);
    expect(names.at(-1)).toBe(SOURCE_TEST_NAME);
    expect(live.at(-1)!.detail).toMatch(/^read \d+ of \d+ files in octocat\/Hello-World as a public repository$/);
    // None of those steps is in the saved report.
    const names2 = ((await reportOf(id))!.data as any).tests.map((t: any) => t.name);
    expect(names2).toEqual([SOURCE_TEST_NAME]);
  });

  it("fails the scan and gives the payment back when the repository could not be read", async (ctx) => {
    if (!githubUp) ctx.skip();
    const missing = `https://github.com/octocat/this-repository-does-not-exist-${Date.now()}`;
    const id = await scan(missing);
    const before = await credits.creditBalance(userId);
    await job.processRepoOnlyJob(base(id, missing));
    expect(await reportOf(id)).toBeUndefined();
    const row = await scanRow(id);
    expect(row.status).toBe("failed");
    expect(String(row.error)).toMatch(/not charged/i);
    expect(await credits.creditBalance(userId)).toBe(before + 1);
  });

  it("fails and refunds for an address that is not a repository", async () => {
    const id = await scan("https://example.com");
    const before = await credits.creditBalance(userId);
    await job.processRepoOnlyJob(base(id, "https://example.com"));
    expect(await reportOf(id)).toBeUndefined();
    const row = await scanRow(id);
    expect(row).toMatchObject({ status: "failed", error: "That is not a GitHub repository address." });
    expect(await credits.creditBalance(userId)).toBe(before + 1);
  });
});

describe("the fix prompt of a repository scan", () => {
  it("is built from the findings, naming the repository and each finding's files", () => {
    const finding = {
      id: "f1", name: "TLS Certificate Verification Disabled", severity: "medium", category: "Transport Security",
      description: "Certificate verification is switched off for outgoing connections.", solution: "Remove the override.",
      evidence: "Repository: acme/app\nFile: server/pgSsl.ts\nCode: rejectUnauthorized: false", cweId: "CWE-295", cvssScore: 5.3, confidence: 70,
    };
    const ai = buildFallbackAnalysis({
      targetUrl: "https://github.com/acme/app", vulnerabilities: [finding as never], tests: [],
      agent: detectAgentEnvironment([], "https://github.com/acme/app"), repository: "acme/app",
    });
    expect(ai.source).toBe("template");
    expect(ai.agentFixPrompt).toContain("in my repository (acme/app)");
    expect(ai.agentFixPrompt).toContain("Where: server/pgSsl.ts");
    expect(ai.agentFixPrompt).not.toContain("rejectUnauthorized");
  });
});
