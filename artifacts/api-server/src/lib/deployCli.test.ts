/**
 * The CLI that the GitHub Action wraps (deploy/cli/secscan.mjs). It lives outside
 * the workspace so it can be published on its own; its tests live here.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { useRealDb, TEST_DATABASE_URL, openDb, startApp, uniqueEmail, type TestApp } from "./realDb.testkit";

useRealDb();
// @ts-ignore -- a plain ESM script with no declaration file
import { parseArgs, countAtOrAbove, policyFailure, formatSummary, run, EXIT } from "../../../../deploy/cli/secscan.mjs";

afterEach(() => {
  delete process.env["SECSCAN_TOKEN"];
});

const TOKEN = ["--token", "ssk_x"];

describe("parseArgs", () => {
  it("takes the URL and defaults sensibly", () => {
    const { opts, error } = parseArgs(["scan", "https://a.example", ...TOKEN]);
    expect(error).toBeUndefined();
    expect(opts).toMatchObject({ url: "https://a.example", failOn: "high", minGrade: null, timeout: 300, token: "ssk_x" });
  });

  it("reads the token from the environment, so it need not appear in a command line", () => {
    process.env["SECSCAN_TOKEN"] = "ssk_env";
    expect(parseArgs(["scan", "https://a.example"]).opts.token).toBe("ssk_env");
  });

  it("refuses without a token, naming where to get one", () => {
    expect(parseArgs(["scan", "https://a.example"]).error).toMatch(/No token/);
  });

  it.each([
    [["scan"], /Give the URL/],
    [["nope", "https://a.example", ...TOKEN], /Usage/],
    [["scan", "https://a.example", "--bogus", ...TOKEN], /Unknown option --bogus/],
    [["scan", "https://a.example", "--fail-on", "urgent", ...TOKEN], /--fail-on/],
    [["scan", "https://a.example", "--min-grade", "Z", ...TOKEN], /--min-grade/],
    [["scan", "https://a.example", "--timeout", "3", ...TOKEN], /--timeout/],
    [["scan", "https://a.example", "--sarif"], /needs a value/],
  ])("rejects bad input %#", (argv, message) => {
    expect(parseArgs(argv).error).toMatch(message);
  });

  it("accepts help without a URL or a token", () => {
    expect(parseArgs(["--help"]).opts.help).toBe(true);
  });
});

describe("policy", () => {
  const findings = { critical: 0, high: 2, medium: 1, low: 0, info: 4, total: 7 };

  it("counts findings at or above a severity", () => {
    expect(countAtOrAbove(findings, "critical")).toBe(0);
    expect(countAtOrAbove(findings, "high")).toBe(2);
    expect(countAtOrAbove(findings, "medium")).toBe(3);
    expect(countAtOrAbove(findings, "info")).toBe(7);
    expect(countAtOrAbove(findings, "none")).toBe(0);
    expect(countAtOrAbove(undefined, "high")).toBe(0);
  });

  it("fails on findings at the chosen level and passes below it", () => {
    expect(policyFailure({ findings }, { failOn: "high", minGrade: null })).toMatch(/2 findings at high or worse/);
    expect(policyFailure({ findings }, { failOn: "critical", minGrade: null })).toBeNull();
    expect(policyFailure({ findings }, { failOn: "none", minGrade: null })).toBeNull();
  });

  it("fails on a grade worse than the minimum", () => {
    expect(policyFailure({ grade: "D", findings: {} }, { failOn: "none", minGrade: "C" })).toMatch(/grade D is worse than C/);
    expect(policyFailure({ grade: "C", findings: {} }, { failOn: "none", minGrade: "C" })).toBeNull();
    expect(policyFailure({ grade: "A", findings: {} }, { failOn: "none", minGrade: "C" })).toBeNull();
  });

  it("does not fail a minimum-grade rule on a scan that has no grade (a bot-protection page), it is reported instead", () => {
    expect(policyFailure({ grade: "N/A", findings: {} }, { failOn: "none", minGrade: "C" })).toBeNull();
    expect(policyFailure({ findings: {} }, { failOn: "none", minGrade: "C" })).toBeNull();
  });
});

describe("formatSummary", () => {
  const scan = { url: "https://a.example", grade: "B", riskScore: 21, findings: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 }, coverage: { ran: 25, skipped: 16, failed: 0, total: 41 }, links: { web: "https://secscan.us/report/r1" } };

  it("says plainly that skipped tests were not checked", () => {
    const text = formatSummary(scan);
    expect(text).toContain("25 ran, 16 skipped, 0 failed");
    expect(text).toContain("skipped tests were NOT checked");
  });

  it("does not print that note when nothing was skipped", () => {
    expect(formatSummary({ ...scan, coverage: { ran: 41, skipped: 0, failed: 0, total: 41 } })).not.toContain("NOT checked");
  });
});

describe.skipIf(!TEST_DATABASE_URL)("run: exit codes (the CLI against the real /api/v1, real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let tokens: typeof import("./apiTokens");
  let app: TestApp;
  let api: string;
  const users: string[] = [];

  /** A user holding a live api-scope token. */
  async function account() {
    const [u] = await dbMod.db.insert(dbMod.usersTable).values({ email: uniqueEmail("cli") }).returning({ id: dbMod.usersTable.id });
    users.push(u!.id);
    const g = tokens.generateToken();
    await dbMod.db.insert(dbMod.apiTokensTable).values({ userId: u!.id, name: "cli", tokenHash: g.hash, prefix: g.prefix, scope: "api" });
    return { id: u!.id, token: g.token };
  }

  /**
   * The scan worker is not running here, so a stand-in for its result is written to the database: once the CLI has created
   * its scan, the row is finished (or failed) with the report the worker would have saved. The API and the CLI are real.
   */
  async function finishWhenCreated(userId: string, result: { status: "complete" | "failed"; error?: string; vulnerabilities?: unknown[]; grade?: string }) {
    for (let i = 0; i < 100; i++) {
      const [scan] = await dbMod.db.select().from(dbMod.scansTable).where(eq(dbMod.scansTable.userId, userId));
      // The API marks the row paid, then queued once the job is on the queue; finish it only after that, or the API overwrites the result.
      if (scan && scan.status === "queued") {
        await dbMod.db.update(dbMod.scansTable).set({ status: result.status, error: result.error ?? null, completedAt: new Date() }).where(eq(dbMod.scansTable.id, scan.id));
        if (result.status === "complete") {
          const tests = [{ group: "g", name: "a", status: "ran", findings: 0, durationMs: 1 }];
          await dbMod.db.insert(dbMod.reportsTable).values({
            scanId: scan.id, userId, targetUrl: scan.targetUrl, tier: "deep", duration: 1,
            data: { summary: { grade: result.grade ?? "B", riskScore: 20 }, vulnerabilities: result.vulnerabilities ?? [], tests } as never,
          });
        }
        return;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("the CLI never created a scan");
  }

  /** The CLI's output channels are parameters of run(); these record what it was told. */
  const io = () => {
    const logs: string[] = [];
    const errs: string[] = [];
    const writes: Array<[string, string]> = [];
    return { logs, errs, writes, io: { log: (m: string) => void logs.push(m), err: (m: string) => void errs.push(m), write: (p: string, d: string) => void writes.push([p, d]) } };
  };
  const target = () => "http://127.0.0.1:9/cli-" + Date.now();

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    tokens = await import("./apiTokens");
    const { default: v1 } = await import("../routes/v1");
    app = startApp(v1 as never);
    api = app.base + "/v1";
  }, 60_000);

  afterAll(async () => {
    app?.server.close();
    const { inArray } = await import("drizzle-orm");
    if (users.length) {
      await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.userId, users));
      await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
      await dbMod.db.delete(dbMod.apiTokensTable).where(inArray(dbMod.apiTokensTable.userId, users));
      await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
    }
    await dbMod?.pool?.end?.();
  });

  it("0 when the scan finishes and passes", async () => {
    const a = await account();
    const o = io();
    const [code] = await Promise.all([run(["scan", target(), "--token", a.token, "--api", api], o.io), finishWhenCreated(a.id, { status: "complete" })]);
    expect(code).toBe(EXIT.ok);
    expect(o.logs).toContain("PASS");
  }, 40_000);

  it("1 when a finding is at the chosen level", async () => {
    const a = await account();
    const o = io();
    const [code] = await Promise.all([
      run(["scan", target(), "--token", a.token, "--api", api], o.io),
      finishWhenCreated(a.id, { status: "complete", vulnerabilities: [{ severity: "high", name: "x", category: "c" }] }),
    ]);
    expect(code).toBe(EXIT.policy);
    expect(o.errs.some((m) => m.includes("FAIL: 1 finding at high or worse"))).toBe(true);
  }, 40_000);

  it("writes SARIF and JSON files when asked", async () => {
    const a = await account();
    const o = io();
    await Promise.all([
      run(["scan", target(), "--token", a.token, "--api", api, "--sarif", "o.sarif", "--json", "o.json"], o.io),
      finishWhenCreated(a.id, { status: "complete", vulnerabilities: [{ name: "Open Redirect Vulnerability", severity: "medium", description: "d", evidence: "GET https://a.example/r", solution: "s" }] }),
    ]);
    const sarif = o.writes.find(([p]) => p === "o.sarif");
    expect(sarif).toBeDefined();
    expect(JSON.parse(sarif![1]).version).toBe("2.1.0");
    expect(o.writes.some(([p]) => p === "o.json")).toBe(true);
  }, 40_000);

  it("2 when the scan itself fails", async () => {
    const a = await account();
    const o = io();
    const [code] = await Promise.all([
      run(["scan", target(), "--token", a.token, "--api", api], o.io),
      finishWhenCreated(a.id, { status: "failed", error: "Failed to reach target URL" }),
    ]);
    expect(code).toBe(EXIT.scan);
    expect(o.errs.some((m) => m.includes("Failed to reach target URL"))).toBe(true);
  }, 40_000);

  it("2 on timeout, and says the scan keeps running", async () => {
    // The scan never finishes. The API holds each status request for up to a minute, so this takes about that long.
    const a = await account();
    const o = io();
    const code = await run(["scan", target(), "--token", a.token, "--api", api, "--timeout", "10"], o.io);
    expect(code).toBe(EXIT.scan);
    expect(o.errs.some((m) => m.includes("keeps running"))).toBe(true);
  }, 120_000);

  it("3 when the token is refused", async () => {
    const o = io();
    expect(await run(["scan", target(), "--token", "ssk_never_issued", "--api", api], o.io)).toBe(EXIT.api);
    expect(o.errs.some((m) => m.includes("Token refused"))).toBe(true);
  });

  it("3 when the API cannot be reached", async () => {
    // Nothing listens on port 1: the connection is genuinely refused.
    expect(await run(["scan", target(), "--token", "ssk_x", "--api", "http://127.0.0.1:1/api/v1"], io().io)).toBe(EXIT.api);
  });

  it("2 for the website's own refusal, such as no scans left", async () => {
    const a = await account();
    for (let i = 0; i < 3; i++) {
      await dbMod.db.insert(dbMod.scansTable).values({ userId: a.id, userEmail: "used@example.com", targetUrl: "https://used.example/", tier: "deep", status: "complete" });
    }
    expect(await run(["scan", target(), "--token", a.token, "--api", api], io().io)).toBe(EXIT.scan);
  }, 20_000);

  it("2 for bad usage, before any request is made", async () => {
    const o = io();
    expect(await run(["scan"], o.io)).toBe(EXIT.scan);
    expect(o.errs.length).toBeGreaterThan(0);
  });
});
