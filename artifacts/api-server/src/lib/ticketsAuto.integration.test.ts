/**
 * Filing Linear and Jira tickets by itself when monitoring finds something new, against a REAL Postgres
 * (BILLING_TEST_DATABASE_URL): the real monitor bookkeeping (recordMonitorScan) on two consecutive scans, the real tables and
 * encryption, and a real local server that answers like Linear and Jira Cloud (ticketStub.testkit.ts).
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb, makeUser } from "./realDb.testkit";
import { startTicketStub, useRealTickets, type TicketStub } from "./ticketStub.testkit";

useRealDb();

const LINEAR_KEY = "lin_api_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4";
const JIRA_TOKEN = "ATATT3xFfGF0" + "Zq8vK2mT9xW4pL7cRn5Bd3Hy";
const SITE = "https://tauto.example.com/";

const vuln = (id: string, name: string, severity: string, category = "Security Headers") =>
  ({ id, name, severity, category, description: `${name} was found.`, evidence: `GET /\n${name}`, solution: "Fix it." });

dbSuiteOf(describe)("automatic Linear and Jira tickets (real Postgres, local Linear and Jira)", () => {
  let dbMod: typeof import("@workspace/db");
  let stub: TicketStub;
  let alice: string;
  const users: string[] = [];
  const reports: string[] = [];
  const subs: string[] = [];

  const linearCreates = () => stub.requests.filter((q) => q.host === "linear" && q.body.includes("issueCreate"));
  const jiraCreates = () => stub.requests.filter((q) => q.host === "jira" && q.method === "POST");
  const linearTitles = () => linearCreates().map((q) => (JSON.parse(q.body) as { variables: { input: { title: string } } }).variables.input.title);
  const jiraTitles = () => jiraCreates().map((q) => (JSON.parse(q.body) as { fields: { summary: string } }).fields.summary);

  async function clearMine() {
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.ticketsTable).where(inArray(dbMod.ticketsTable.userId, users));
    await dbMod.db.delete(dbMod.ticketDestinationsTable).where(inArray(dbMod.ticketDestinationsTable.userId, users));
  }

  function providersAccept() {
    let l = 20, j = 30;
    stub.on("POST", "linear", "/graphql", (r) => {
      const { query } = JSON.parse(r.body) as { query: string };
      if (query.includes("teams(")) return { json: { data: { teams: { nodes: [{ id: "team-id", key: "ENG" }] } } } };
      l += 1;
      return { json: { data: { issueCreate: { success: true, issue: { identifier: `ENG-${l}`, url: `https://linear.app/acme/issue/ENG-${l}` } } } } };
    });
    stub.on("GET", "jira", "/rest/api/3/project/SEC", { json: { key: "SEC", issueTypes: [{ name: "Task" }] } });
    stub.on("POST", "jira", "/rest/api/3/issue", () => { j += 1; return { status: 201, json: { id: String(j), key: `SEC-${j}` } }; });
  }

  async function connect(which: { linear?: boolean | string; jira?: boolean | string }) {
    const { saveDestination, setAutoFile } = await import("./tickets");
    if (which.linear !== undefined) {
      expect((await saveDestination(alice, { provider: "linear", team: "eng", apiKey: LINEAR_KEY })).ok).toBe(true);
      if (which.linear) await setAutoFile(alice, "linear", true, which.linear === true ? "high" : (which.linear as "critical"));
    }
    if (which.jira !== undefined) {
      expect((await saveDestination(alice, { provider: "jira", site: "acme", email: "dev@acme.com", token: JIRA_TOKEN, project: "sec" })).ok).toBe(true);
      if (which.jira) await setAutoFile(alice, "jira", true, which.jira === true ? "high" : (which.jira as "critical"));
    }
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

  beforeAll(async () => {
    process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
    dbMod = await openDb();
    stub = await startTicketStub();
    alice = await makeUser(dbMod, "tkauto-alice");
    users.push(alice);
  }, 60_000);

  beforeEach(async () => {
    stub.clear();
    providersAccept();
    await clearMine();
  });

  afterAll(async () => {
    await stub.stop();
    useRealTickets();
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

  it("files nothing while the switch is off, and still records the regressions", async () => {
    await connect({ linear: false, jira: false });
    stub.requests.length = 0;
    const { subscriptionId } = await monitorScan([old], [old, newHigh, newCritical]);
    expect(linearCreates()).toHaveLength(0);
    expect(jiraCreates()).toHaveLength(0);
    const { eq } = await import("drizzle-orm");
    const rows = await dbMod.db.select().from(dbMod.monitorRegressionsTable).where(eq(dbMod.monitorRegressionsTable.subscriptionId, subscriptionId));
    expect(rows.map((x) => x.checkTitle).sort()).toEqual(["New critical finding", "New high finding"]);
  });

  it("files only the new findings at or above the floor, most severe first, in each system that is on", async () => {
    await connect({ linear: true, jira: true });
    stub.requests.length = 0;
    await monitorScan([old], [old, newHigh, newCritical, newLow]);
    for (const titles of [linearTitles(), jiraTitles()]) {
      expect(titles).toHaveLength(2);
      expect(titles[0]).toContain("New critical finding");
      expect(titles[1]).toContain("New high finding");
    }
    const { eq } = await import("drizzle-orm");
    expect(await dbMod.db.select().from(dbMod.ticketsTable).where(eq(dbMod.ticketsTable.userId, alice))).toHaveLength(4);
  });

  it("each system has its own switch and its own floor", async () => {
    await connect({ linear: "critical", jira: false });
    stub.requests.length = 0;
    await monitorScan([old], [old, newHigh, newCritical]);
    expect(linearTitles()).toHaveLength(1);
    expect(linearTitles()[0]).toContain("New critical finding");
    expect(jiraCreates()).toHaveLength(0);
  });

  it("does not file a second ticket for a problem that already has one", async () => {
    await connect({ linear: true });
    const { fileTicket } = await import("./tickets");
    const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId: alice, userEmail: "x@example.com", targetUrl: SITE, tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
    const [rep] = await dbMod.db.insert(dbMod.reportsTable).values({ scanId: scan!.id, userId: alice, targetUrl: SITE, tier: "deep", duration: 1, data: { vulnerabilities: [newHigh] } as never }).returning({ id: dbMod.reportsTable.id });
    reports.push(rep!.id);
    expect((await fileTicket({ userId: alice, provider: "linear", reportId: rep!.id, findingId: "n1" })).ok).toBe(true);
    stub.requests.length = 0;

    await monitorScan([old], [old, newHigh, newCritical]);
    expect(linearTitles()).toHaveLength(1);
    expect(linearTitles()[0]).toContain("New critical finding");
  });

  it("files nothing when nothing is new", async () => {
    await connect({ linear: true, jira: true });
    stub.requests.length = 0;
    await monitorScan([old, newHigh], [old, newHigh]);
    expect(linearCreates()).toHaveLength(0);
    expect(jiraCreates()).toHaveLength(0);
  });

  it("stops at MAX_PER_SCAN in each system", async () => {
    await connect({ linear: true, jira: true });
    stub.requests.length = 0;
    const { MAX_PER_SCAN } = await import("./githubIssuesAuto");
    const many = Array.from({ length: MAX_PER_SCAN + 5 }, (_, i) => vuln(`m${i}`, `Distinct critical finding number ${i}`, "critical"));
    await monitorScan([old], [old, ...many]);
    expect(linearCreates()).toHaveLength(MAX_PER_SCAN);
    expect(jiraCreates()).toHaveLength(MAX_PER_SCAN);
  });

  it("a rejected credential stops that system only, loses nothing else, and does not fail the scan", async () => {
    await connect({ linear: true, jira: true });
    stub.requests.length = 0;
    stub.on("POST", "linear", "/graphql", { status: 401, json: { errors: [{ message: "Authentication required", extensions: { type: "authentication error" } }] } });
    await monitorScan([old], [old, newHigh, newCritical]);
    expect(linearCreates()).toHaveLength(1); // asked once, not once per finding
    expect(jiraCreates()).toHaveLength(2); // Jira is unaffected
    const { eq } = await import("drizzle-orm");
    const rows = await dbMod.db.select().from(dbMod.ticketsTable).where(eq(dbMod.ticketsTable.userId, alice));
    expect(rows.map((r) => r.provider)).toEqual(["jira", "jira"]);
  });

  it("redacts secrets and leaves no mention live, exactly as a click does", async () => {
    await connect({ linear: true, jira: true });
    stub.requests.length = 0;
    const leaky = { ...vuln("n9", "Secret in a file", "critical"), description: "Ask @octocat to look.", evidence: "GET /.env\nJWT_SECRET=Zq8vK2mT9xW4pL7cRn5Bd3Hy" };
    await monitorScan([old], [old, leaky]);
    const linearBody = (JSON.parse(linearCreates()[0]!.body) as { variables: { input: { description: string } } }).variables.input.description;
    const jiraBody = jiraCreates()[0]!.body;
    for (const body of [linearBody, jiraBody]) expect(body).not.toContain("Zq8vK2mT9xW4pL7cRn5Bd3Hy");
    expect(linearBody).not.toMatch(/(^|[^`\w])@octocat/);
  });
});
