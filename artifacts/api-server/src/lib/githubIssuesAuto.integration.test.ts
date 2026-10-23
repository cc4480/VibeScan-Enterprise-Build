/**
 * Filing GitHub issues by itself when monitoring finds something new, against a REAL Postgres (BILLING_TEST_DATABASE_URL):
 * the real monitor bookkeeping (recordMonitorScan) on two consecutive scans, the real routes and tables and encryption, and
 * a real local server that answers like GitHub (githubStub.testkit.ts) in place of api.github.com.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "./realDb.testkit";
import { startGithubStub, useRealGithub, type GithubStub } from "./githubStub.testkit";

useRealDb();

const TOKEN = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
const REPO = "acme/website";
const SITE = "https://auto.example.com/";

const vuln = (id: string, name: string, severity: string, category = "Security Headers") =>
  ({ id, name, severity, category, description: `${name} was found.`, evidence: `GET /\n${name}`, solution: "Fix it." });

// Imported inside the tests: these modules open the database pool when loaded, which has to wait for useRealDb().
const auto = () => import("./githubIssuesAuto");

describe("selectForFiling", () => {
  const r = (severity: string) => ({ severity, name: severity });
  it("keeps what is at or above the floor, most severe first", async () => {
    const { selectForFiling } = await auto();
    expect(selectForFiling([r("low"), r("medium"), r("high"), r("critical"), r("info")], "high").map((x) => x.severity)).toEqual(["critical", "high"]);
    expect(selectForFiling([r("medium"), r("critical")], "medium").map((x) => x.severity)).toEqual(["critical", "medium"]);
    expect(selectForFiling([r("high"), r("critical")], "critical").map((x) => x.severity)).toEqual(["critical"]);
  });
  it("reads severities in either case, and files nothing it cannot read", async () => {
    const { selectForFiling } = await auto();
    expect(selectForFiling([r("CRITICAL"), r("banana")], "medium")).toHaveLength(1);
  });
  it("never more than MAX_PER_SCAN", async () => {
    const { selectForFiling, MAX_PER_SCAN } = await auto();
    expect(selectForFiling(Array.from({ length: 25 }, () => r("critical")), "high")).toHaveLength(MAX_PER_SCAN);
  });
});

dbSuiteOf(describe)("automatic GitHub issues (real Postgres, local GitHub)", () => {
  let dbMod: typeof import("@workspace/db");
  let gh: GithubStub;
  let app: TestApp;
  let alice: string;
  const users: string[] = [];
  const reports: string[] = [];
  const subs: string[] = [];

  type Answer = { status: number; json(): Promise<any> }; // eslint-disable-line @typescript-eslint/no-explicit-any
  const api = (path: string, init: { method?: string; body?: unknown } = {}): Promise<Answer> =>
    fetch(`${app.base}${path}`, {
      method: init.method ?? "GET",
      headers: { "content-type": "application/json" },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });
  const posted = () => gh.requests.filter((q) => q.method === "POST" && q.path === `/repos/${REPO}/issues`);
  const titles = () => posted().map((q) => (JSON.parse(q.body) as { title: string }).title);

  async function clearMine() {
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.githubIssuesTable).where(inArray(dbMod.githubIssuesTable.userId, users));
    await dbMod.db.delete(dbMod.githubIssueDestinationsTable).where(inArray(dbMod.githubIssueDestinationsTable.userId, users));
  }

  function githubAccepts() {
    let next = 100;
    gh.on("GET", "api", `/repos/${REPO}`, { json: { full_name: REPO, has_issues: true, archived: false } });
    gh.on("POST", "api", `/repos/${REPO}/issues`, () => {
      next += 1;
      return { status: 201, json: { number: next, html_url: `https://github.com/${REPO}/issues/${next}` } };
    });
  }

  async function connect(auto?: { enabled: boolean; minSeverity?: string }) {
    const { saveDestination } = await import("./githubIssues");
    expect((await saveDestination(alice, REPO, TOKEN)).ok).toBe(true);
    if (auto) expect((await api("/integrations/github-issues/auto", { method: "PATCH", body: auto })).status).toBe(200);
  }

  /** A monitored site with one finished scan behind it (`before`), then a new one (`now`) run through the real bookkeeping. */
  async function monitorScan(before: ReturnType<typeof vuln>[], now: ReturnType<typeof vuln>[]) {
    const [sub] = await dbMod.db.insert(dbMod.monitorSubscriptionsTable).values({
      userId: alice, userEmail: "", targetUrl: SITE, expiresAt: new Date(Date.now() + 86_400_000),
    }).returning({ id: dbMod.monitorSubscriptionsTable.id });
    subs.push(sub!.id);

    const finish = async (vulns: ReturnType<typeof vuln>[], at: Date) => {
      const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId: alice, userEmail: "x@example.com", targetUrl: SITE, tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
      const [rep] = await dbMod.db.insert(dbMod.reportsTable).values({
        scanId: scan!.id, userId: alice, targetUrl: SITE, tier: "deep", duration: 1, data: { summary: { grade: "C", riskScore: 50 }, vulnerabilities: vulns, tests: [] } as never,
      }).returning({ id: dbMod.reportsTable.id });
      reports.push(rep!.id);
      return { scanId: scan!.id, reportId: rep!.id, at };
    };

    const first = await finish(before, new Date(Date.now() - 7 * 86_400_000));
    await dbMod.db.insert(dbMod.monitorScoreHistoryTable).values({ subscriptionId: sub!.id, scanId: first.scanId, grade: "C", riskScore: 50, scannedAt: first.at });
    const second = await finish(now, new Date());

    const { recordMonitorScan } = await import("./workerMonitor");
    const { logger } = await import("./logger");
    await recordMonitorScan({
      monitorSubscriptionId: sub!.id, userId: alice, scanId: second.scanId, reportId: second.reportId, targetUrl: SITE, grade: "C", riskScore: 50,
      completedAt: second.at, intercepted: false, severityCounts: {}, tests: [], vulnerabilities: now as never, log: logger,
    });
    return { subscriptionId: sub!.id };
  }

  async function regressionTitles(subscriptionId: string) {
    const { eq } = await import("drizzle-orm");
    const rows = await dbMod.db.select().from(dbMod.monitorRegressionsTable).where(eq(dbMod.monitorRegressionsTable.subscriptionId, subscriptionId));
    return rows.map((x) => x.checkTitle).sort();
  }

  beforeAll(async () => {
    process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
    dbMod = await openDb();
    gh = await startGithubStub();
    const router = (await import("../routes/githubIssues")).default;
    app = startApp(router);
    alice = await makeUser(dbMod, "ghauto-alice");
    users.push(alice);
    app.as({ id: alice });
  }, 60_000);

  beforeEach(async () => {
    gh.clear();
    githubAccepts();
    await clearMine();
  });

  afterAll(async () => {
    app.server.close();
    await gh.stop();
    useRealGithub();
    const { inArray } = await import("drizzle-orm");
    await clearMine();
    if (subs.length) await dbMod.db.delete(dbMod.monitorSubscriptionsTable).where(inArray(dbMod.monitorSubscriptionsTable.id, subs));
    if (reports.length) await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.id, reports));
    await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
  });

  const old = vuln("o1", "Old finding that was already there", "high");
  const newHigh = vuln("n1", "New high finding", "high");
  const newCritical = vuln("n2", "New critical finding", "critical", "Information Disclosure");
  const newLow = vuln("n3", "New low finding", "low");

  describe("the setting", () => {
    it("is off by default, and needs a signed-in account and a connected repository", async () => {
      app.as(null);
      expect((await api("/integrations/github-issues/auto", { method: "PATCH", body: { enabled: true } })).status).toBe(401);
      app.as({ id: alice });
      expect((await api("/integrations/github-issues/auto", { method: "PATCH", body: { enabled: true } })).status).toBe(409);
      await connect();
      const got = await (await api("/integrations/github-issues")).json();
      expect([got.autoFile, got.autoMinSeverity]).toEqual([false, "high"]);
    });

    it("saves on, off and the floor, and refuses a floor that is not offered", async () => {
      await connect();
      expect(await (await api("/integrations/github-issues/auto", { method: "PATCH", body: { enabled: true, minSeverity: "critical" } })).json()).toEqual({ autoFile: true, autoMinSeverity: "critical" });
      expect((await (await api("/integrations/github-issues")).json()).autoMinSeverity).toBe("critical");
      // Turning it off keeps the floor chosen before.
      expect(await (await api("/integrations/github-issues/auto", { method: "PATCH", body: { enabled: false } })).json()).toEqual({ autoFile: false, autoMinSeverity: "critical" });
      for (const body of [{}, { enabled: "yes" }, { enabled: true, minSeverity: "low" }, { enabled: true, minSeverity: "info" }]) {
        expect((await api("/integrations/github-issues/auto", { method: "PATCH", body })).status).toBe(400);
      }
    });

    it("switches itself off when the account points at a different repository, and not for the same one", async () => {
      await connect({ enabled: true });
      const { saveDestination } = await import("./githubIssues");
      expect((await saveDestination(alice, REPO, TOKEN)).ok).toBe(true); // a new token, same repository
      expect((await (await api("/integrations/github-issues")).json()).autoFile).toBe(true);
      gh.on("GET", "api", "/repos/acme/other", { json: { full_name: "acme/other", has_issues: true, archived: false } });
      expect((await saveDestination(alice, "acme/other", TOKEN)).ok).toBe(true);
      expect((await (await api("/integrations/github-issues")).json()).autoFile).toBe(false);
    });
  });

  describe("a monitored scan that finds something new", () => {
    it("files nothing while the setting is off", async () => {
      await connect();
      const { subscriptionId } = await monitorScan([old], [old, newHigh, newCritical]);
      expect(posted()).toHaveLength(0);
      // The regressions were still recorded: the rest of the bookkeeping is untouched.
      expect(await regressionTitles(subscriptionId)).toEqual(["New critical finding", "New high finding"]);
    });

    it("files only the new findings at or above the floor, once each", async () => {
      await connect({ enabled: true, minSeverity: "high" });
      await monitorScan([old], [old, newHigh, newCritical, newLow]);
      // Not the finding that was already there, and not the low one. Most severe first.
      expect(titles()).toHaveLength(2);
      expect(titles()[0]).toContain("New critical finding");
      expect(titles()[1]).toContain("New high finding");
      const { eq } = await import("drizzle-orm");
      expect(await dbMod.db.select().from(dbMod.githubIssuesTable).where(eq(dbMod.githubIssuesTable.userId, alice))).toHaveLength(2);
    });

    it("honours a higher floor", async () => {
      await connect({ enabled: true, minSeverity: "critical" });
      await monitorScan([old], [old, newHigh, newCritical]);
      expect(titles()).toHaveLength(1);
      expect(titles()[0]).toContain("New critical finding");
    });

    it("does not file a second issue for a problem that already has one", async () => {
      await connect({ enabled: true });
      // The same problem on the same site, filed earlier by a click.
      const { fileIssue } = await import("./githubIssues");
      const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId: alice, userEmail: "x@example.com", targetUrl: SITE, tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
      const [rep] = await dbMod.db.insert(dbMod.reportsTable).values({ scanId: scan!.id, userId: alice, targetUrl: SITE, tier: "deep", duration: 1, data: { vulnerabilities: [newHigh] } as never }).returning({ id: dbMod.reportsTable.id });
      reports.push(rep!.id);
      expect((await fileIssue({ userId: alice, reportId: rep!.id, findingId: "n1" })).ok).toBe(true);
      gh.clear();
      githubAccepts();

      await monitorScan([old], [old, newHigh, newCritical]);
      expect(titles()).toHaveLength(1);
      expect(titles()[0]).toContain("New critical finding");
    });

    it("files nothing when nothing is new", async () => {
      await connect({ enabled: true });
      await monitorScan([old, newHigh], [old, newHigh]);
      expect(posted()).toHaveLength(0);
    });

    it("stops at MAX_PER_SCAN", async () => {
      await connect({ enabled: true });
      const { MAX_PER_SCAN } = await auto();
      const many = Array.from({ length: MAX_PER_SCAN + 5 }, (_, i) => vuln(`m${i}`, `Distinct critical finding number ${i}`, "critical"));
      await monitorScan([old], [old, ...many]);
      expect(posted()).toHaveLength(MAX_PER_SCAN);
    });

    it("a rejected token stops the filing, loses nothing else, and does not fail the scan", async () => {
      await connect({ enabled: true });
      gh.on("POST", "api", `/repos/${REPO}/issues`, { status: 401, json: { message: "Bad credentials" } });
      const { subscriptionId } = await monitorScan([old], [old, newHigh, newCritical]);
      expect(posted()).toHaveLength(1); // asked once, not once per finding
      expect(await regressionTitles(subscriptionId)).toEqual(["New critical finding", "New high finding"]);
      const { eq } = await import("drizzle-orm");
      expect(await dbMod.db.select().from(dbMod.githubIssuesTable).where(eq(dbMod.githubIssuesTable.userId, alice))).toHaveLength(0);
    });

    it("redacts secrets and leaves no mention live, exactly as a click does", async () => {
      await connect({ enabled: true });
      const leaky = { ...vuln("n9", "Secret in a file", "critical"), description: "Ask @octocat to look.", evidence: "GET /.env\nJWT_SECRET=Zq8vK2mT9xW4pL7cRn5Bd3Hy" };
      await monitorScan([old], [old, leaky]);
      const body = (JSON.parse(posted()[0]!.body) as { body: string }).body;
      expect(body).not.toContain("Zq8vK2mT9xW4pL7cRn5Bd3Hy");
      expect(body).not.toMatch(/(^|[^`\w])@octocat/);
    });
  });
});
