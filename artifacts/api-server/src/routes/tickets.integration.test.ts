/**
 * File findings as Linear issues and Jira tickets, over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): the
 * real routes, the real tables, the real encryption, and a real local server that answers like Linear and Jira Cloud
 * (lib/ticketStub.testkit.ts) in place of their own hosts. The stub only decides what they would answer and records what it
 * was asked.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "../lib/realDb.testkit";
import { startTicketStub, useRealTickets, type TicketStub } from "../lib/ticketStub.testkit";

useRealDb();

const LINEAR_KEY = "lin_api_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4";
const JIRA_TOKEN = "ATATT3xFfGF0" + "Zq8vK2mT9xW4pL7cRn5Bd3Hy";
const SECRET_LINE = "JWT_SECRET=Zq8vK2mT9xW4pL7cRn5Bd3Hy";
const LINEAR = { team: "eng", apiKey: LINEAR_KEY };
const JIRA = { site: "acme", email: "dev@acme.com", token: JIRA_TOKEN, project: "sec" };

dbSuiteOf(describe)("Linear and Jira tickets for findings (real Postgres, local Linear and Jira)", () => {
  let dbMod: typeof import("@workspace/db");
  let stub: TicketStub;
  let app: TestApp;
  const users: string[] = [];
  const reports: string[] = [];
  let alice: { id: string; email: string };
  let bob: { id: string; email: string };

  type Answer = { status: number; json(): Promise<any>; text(): Promise<string> }; // eslint-disable-line @typescript-eslint/no-explicit-any
  const api = (path: string, init: { method?: string; body?: unknown } = {}): Promise<Answer> =>
    fetch(`${app.base}${path}`, {
      method: init.method ?? "GET",
      headers: { "content-type": "application/json" },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });
  const asAlice = () => app.as(alice);

  async function destRows() {
    const { inArray } = await import("drizzle-orm");
    return dbMod.db.select().from(dbMod.ticketDestinationsTable).where(inArray(dbMod.ticketDestinationsTable.userId, users));
  }
  async function ticketRows() {
    const { inArray } = await import("drizzle-orm");
    return dbMod.db.select().from(dbMod.ticketsTable).where(inArray(dbMod.ticketsTable.userId, users));
  }

  async function report(userId: string, targetUrl = "https://shop.example.com/", over: Array<Record<string, unknown>> = []) {
    const vulnerabilities = [
      { id: "f-csp", name: "Missing Content-Security-Policy (CSP)", severity: "high", category: "Security Headers", description: "No CSP header.\n\nAdd one.", evidence: "GET /\nNo CSP header.", solution: "Add one.", cweId: "CWE-693", wstgId: "WSTG-CONF-12" },
      { id: "f-env", name: "Environment File Exposed (.env)", severity: "critical", category: "Information Disclosure", description: "The .env file is served. Ask @octocat to look.", evidence: `GET /.env\n${SECRET_LINE}`, solution: "Remove it." },
      { id: "f-cov", name: "Active security testing was skipped", severity: "info", category: "Scan Coverage", description: "Not verified.", evidence: "", solution: "" },
      ...over,
    ];
    const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId, userEmail: "x@example.com", targetUrl, tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
    const [r] = await dbMod.db.insert(dbMod.reportsTable).values({
      scanId: scan!.id, userId, targetUrl, tier: "deep", duration: 1, data: { summary: { grade: "C", riskScore: 50 }, vulnerabilities, tests: [] } as never,
    }).returning({ id: dbMod.reportsTable.id });
    reports.push(r!.id);
    return r!.id;
  }

  /** Linear accepting the key, knowing team ENG, and creating issues with increasing numbers. */
  function linearAccepts() {
    let next = 11;
    stub.on("POST", "linear", "/graphql", (r) => {
      const { query, variables } = JSON.parse(r.body) as { query: string; variables: Record<string, any> }; // eslint-disable-line @typescript-eslint/no-explicit-any
      if (query.includes("teams(")) {
        return { json: { data: { teams: { nodes: variables["key"] === "ENG" ? [{ id: "team-eng-id", key: "ENG" }] : [] } } } };
      }
      next += 1;
      return { json: { data: { issueCreate: { success: true, issue: { identifier: `ENG-${next}`, url: `https://linear.app/acme/issue/ENG-${next}/x` } } } } };
    });
  }
  /** Jira accepting the token, knowing project SEC with a Task and a Bug type, and creating tickets with increasing numbers. */
  function jiraAccepts() {
    let next = 6;
    stub.on("GET", "jira", "/rest/api/3/project/SEC", { json: { key: "SEC", issueTypes: [{ name: "Task" }, { name: "Bug" }] } });
    stub.on("POST", "jira", "/rest/api/3/issue", () => { next += 1; return { status: 201, json: { id: String(1000 + next), key: `SEC-${next}` } }; });
  }
  const linearCreates = () => stub.requests.filter((r) => r.host === "linear" && r.body.includes("issueCreate"));
  const jiraCreates = () => stub.requests.filter((r) => r.host === "jira" && r.method === "POST");
  const linearInput = (i = 0) => (JSON.parse(linearCreates()[i]!.body) as { variables: { input: Record<string, any> } }).variables.input; // eslint-disable-line @typescript-eslint/no-explicit-any
  const jiraFields = (i = 0) => (JSON.parse(jiraCreates()[i]!.body) as { fields: Record<string, any> }).fields; // eslint-disable-line @typescript-eslint/no-explicit-any

  beforeAll(async () => {
    process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
    dbMod = await openDb();
    stub = await startTicketStub();
    const router = (await import("./tickets")).default;
    app = startApp(router);
    alice = { id: await makeUser(dbMod, "tk-alice"), email: "alice@example.com" };
    bob = { id: await makeUser(dbMod, "tk-bob"), email: "bob@example.com" };
    users.push(alice.id, bob.id);
  }, 60_000);

  beforeEach(async () => {
    stub.clear();
    app.as(null);
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.ticketsTable).where(inArray(dbMod.ticketsTable.userId, users));
    await dbMod.db.delete(dbMod.ticketDestinationsTable).where(inArray(dbMod.ticketDestinationsTable.userId, users));
  });

  afterAll(async () => {
    app.server.close();
    await stub.stop();
    useRealTickets();
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.ticketsTable).where(inArray(dbMod.ticketsTable.userId, users));
    await dbMod.db.delete(dbMod.ticketDestinationsTable).where(inArray(dbMod.ticketDestinationsTable.userId, users));
    if (reports.length) await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.id, reports));
    await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
  });

  describe("connecting", () => {
    const ZERO = `${"0".repeat(8)}-0000-0000-0000-${"0".repeat(12)}`;

    it("every route needs a signed-in account", async () => {
      expect((await api("/integrations/tickets")).status).toBe(401);
      expect((await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR })).status).toBe(401);
      expect((await api("/integrations/tickets/jira", { method: "DELETE" })).status).toBe(401);
      expect((await api("/integrations/tickets/jira/auto", { method: "PATCH", body: { enabled: true } })).status).toBe(401);
      expect((await api(`/reports/${ZERO}/ticket`, { method: "POST", body: { provider: "linear", findingId: "x" } })).status).toBe(401);
      expect((await api(`/reports/${ZERO}/tickets`)).status).toBe(401);
    });

    it("starts with nothing connected, and knows only linear and jira", async () => {
      asAlice();
      expect(await (await api("/integrations/tickets")).json()).toEqual({ available: true, destinations: [] });
      expect((await api("/integrations/tickets/trello", { method: "PUT", body: LINEAR })).status).toBe(404);
      expect((await api("/integrations/tickets/trello", { method: "DELETE" })).status).toBe(404);
    });

    it("Linear: checks the key against the team, stores it encrypted, and never returns it", async () => {
      linearAccepts();
      asAlice();
      const res = await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ configured: true, provider: "linear", target: "ENG" });
      // Linear was asked with the key as is (a personal API key takes no "Bearer").
      expect(stub.requests[0]!.headers["authorization"]).toBe(LINEAR_KEY);
      const [row] = await destRows();
      expect(row).toMatchObject({ provider: "linear", target: "ENG", externalId: "team-eng-id" });
      expect(row!.credentialEncrypted).not.toContain(LINEAR_KEY);
      expect(row!.credentialEncrypted.split(".")).toHaveLength(3);
      const listed = await (await api("/integrations/tickets")).text();
      expect(listed).not.toContain(LINEAR_KEY);
      expect(JSON.parse(listed).destinations).toEqual([{ provider: "linear", target: "ENG", site: null, accountEmail: null, issueType: null, autoFile: false, autoMinSeverity: "high" }]);
    });

    it("Jira: checks the token against the project, stores it encrypted, and never returns it", async () => {
      jiraAccepts();
      asAlice();
      const res = await api("/integrations/tickets/jira", { method: "PUT", body: JIRA });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ configured: true, provider: "jira", target: "SEC" });
      const check = stub.requests[0]!;
      expect(check.headers["authorization"]).toBe(`Basic ${Buffer.from(`${JIRA.email}:${JIRA_TOKEN}`).toString("base64")}`);
      const [row] = await destRows();
      expect(row).toMatchObject({ provider: "jira", target: "SEC", site: "acme.atlassian.net", accountEmail: JIRA.email, issueType: "Task" });
      expect(row!.credentialEncrypted).not.toContain(JIRA_TOKEN);
      expect(await (await api("/integrations/tickets")).text()).not.toContain(JIRA_TOKEN);
    });

    it("keeps Linear and Jira side by side, and each account has its own", async () => {
      linearAccepts(); jiraAccepts();
      asAlice();
      await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR });
      await api("/integrations/tickets/jira", { method: "PUT", body: JIRA });
      expect((await (await api("/integrations/tickets")).json()).destinations.map((d: { provider: string }) => d.provider).sort()).toEqual(["jira", "linear"]);
      app.as(bob);
      expect((await (await api("/integrations/tickets")).json()).destinations).toEqual([]);
      asAlice();
      await api("/integrations/tickets/jira", { method: "DELETE" });
      expect((await (await api("/integrations/tickets")).json()).destinations.map((d: { provider: string }) => d.provider)).toEqual(["linear"]);
    });

    it.each([
      ["Linear: a team key that is not one", "linear", { team: "not a team", apiKey: LINEAR_KEY }, "bad_team"],
      ["Linear: something that is not a key", "linear", { team: "ENG", apiKey: "not a key!!" + "x".repeat(20) }, "bad_token"],
      ["Jira: a site on another host", "jira", { ...JIRA, site: "https://evil.example.com" }, "bad_site"],
      ["Jira: a site with a port or path trick", "jira", { ...JIRA, site: "acme.atlassian.net.evil.com" }, "bad_site"],
      ["Jira: an email that is not one", "jira", { ...JIRA, email: "nobody" }, "bad_email"],
      ["Jira: a project key that is not one", "jira", { ...JIRA, project: "not a key" }, "bad_project"],
    ])("refuses %s without calling the provider", async (_label, provider, body, code) => {
      asAlice();
      const res = await api(`/integrations/tickets/${provider}`, { method: "PUT", body });
      expect(res.status).toBe(400);
      expect((await res.json()).code).toBe(code);
      expect(stub.requests).toHaveLength(0);
    });

    it("refuses a missing body", async () => {
      asAlice();
      expect((await api("/integrations/tickets/linear", { method: "PUT", body: { team: "ENG" } })).status).toBe(400);
      expect((await api("/integrations/tickets/jira", { method: "PUT", body: { site: "acme" } })).status).toBe(400);
    });

    it.each([
      ["Linear: a key it rejects", "linear", LINEAR, { status: 401, json: { errors: [{ message: "Authentication required", extensions: { type: "authentication error" } }] } }, 401, "token_rejected"],
      ["Linear: a team the key cannot see", "linear", { ...LINEAR, team: "NOPE" }, { json: { data: { teams: { nodes: [] } } } }, 404, "team_not_visible"],
      ["Linear failing", "linear", LINEAR, { status: 500, json: {} }, 502, "linear_error"],
      ["Jira: a token it rejects", "jira", JIRA, { status: 401, json: {} }, 401, "token_rejected"],
      ["Jira: a project the account cannot see", "jira", JIRA, { status: 404, json: {} }, 404, "project_not_visible"],
      ["Jira: a project without the issue type", "jira", { ...JIRA, issueType: "Epic" }, { json: { key: "SEC", issueTypes: [{ name: "Task" }, { name: "Bug" }] } }, 409, "issue_type_missing"],
      ["Jira failing", "jira", JIRA, { status: 500, json: {} }, 502, "jira_error"],
    ])("explains %s, and saves nothing", async (_label, provider, body, reply, status, code) => {
      if (provider === "linear") stub.on("POST", "linear", "/graphql", reply); else stub.on("GET", "jira", "/rest/api/3/project/SEC", reply);
      asAlice();
      const res = await api(`/integrations/tickets/${provider}`, { method: "PUT", body });
      expect(res.status).toBe(status);
      expect((await res.json()).code).toBe(code);
      expect(await destRows()).toHaveLength(0);
    });

    it("says so when the provider cannot be reached", async () => {
      process.env["LINEAR_API_URL"] = "http://127.0.0.1:1"; // nothing listens on port 1: genuinely refused
      try {
        asAlice();
        const res = await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR });
        expect(res.status).toBe(502);
        expect((await res.json()).code).toBe("linear_unreachable");
      } finally {
        process.env["LINEAR_API_URL"] = stub.linear;
      }
    });

    it("never follows a redirect with the credential", async () => {
      stub.on("GET", "jira", "/rest/api/3/project/SEC", { status: 302, text: "" });
      asAlice();
      const res = await api("/integrations/tickets/jira", { method: "PUT", body: JIRA });
      expect(res.status).toBe(502);
      expect(await destRows()).toHaveLength(0);
    });
  });

  describe("automatic filing switch", () => {
    it("is off until turned on, needs a connection, and is switched off when the destination changes", async () => {
      linearAccepts(); jiraAccepts();
      asAlice();
      expect((await api("/integrations/tickets/linear/auto", { method: "PATCH", body: { enabled: true } })).status).toBe(409);
      await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR });
      expect(await (await api("/integrations/tickets/linear/auto", { method: "PATCH", body: { enabled: true, minSeverity: "medium" } })).json()).toEqual({ autoFile: true, autoMinSeverity: "medium" });
      expect((await destRows())[0]).toMatchObject({ autoFile: true, autoMinSeverity: "medium" });
      // Saving the same team again keeps it; a different team (agreed for the old one) switches it off.
      await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR });
      expect((await destRows())[0]!.autoFile).toBe(true);
      stub.on("POST", "linear", "/graphql", { json: { data: { teams: { nodes: [{ id: "team-ops-id", key: "OPS" }] } } } });
      await api("/integrations/tickets/linear", { method: "PUT", body: { ...LINEAR, team: "ops" } });
      expect((await destRows())[0]).toMatchObject({ target: "OPS", autoFile: false });
      expect((await api("/integrations/tickets/jira/auto", { method: "PATCH", body: { enabled: "yes" } })).status).toBe(400);
    });
  });

  describe("filing a Linear issue", () => {
    async function connect() {
      linearAccepts();
      asAlice();
      expect((await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR })).status).toBe(200);
      stub.requests.length = 0;
    }
    const file = (reportId: string, findingId: string) => api(`/reports/${reportId}/ticket`, { method: "POST", body: { provider: "linear", findingId } });

    it("creates the issue in the team, with a title, a markdown body and a priority", async () => {
      await connect();
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(201);
      expect(await res.json()).toEqual({ created: true, provider: "linear", ticketKey: "ENG-12", ticketUrl: "https://linear.app/acme/issue/ENG-12/x" });
      expect(linearCreates()).toHaveLength(1);
      expect(linearCreates()[0]!.headers["authorization"]).toBe(LINEAR_KEY);
      const input = linearInput();
      expect(input["teamId"]).toBe("team-eng-id");
      expect(input["title"]).toBe("[SecScan] High: Missing Content-Security-Policy (CSP) (shop.example.com)");
      expect(input["priority"]).toBe(2);
      expect(input["description"]).toContain("No CSP header.");
      expect(input["description"]).toContain(`/report/${reportId}`);
    });

    it("keeps secrets and mentions out of what it sends", async () => {
      await connect();
      const reportId = await report(alice.id);
      expect((await file(reportId, "f-env")).status).toBe(201);
      const input = linearInput();
      expect(input["priority"]).toBe(1);
      expect(input["description"]).not.toContain("Zq8vK2mT9xW4pL7cRn5Bd3Hy");
      expect(input["description"]).toContain("JWT_SECRET=<redacted>");
      expect(input["description"]).not.toMatch(/@(?=octocat)/);
    });

    it("files the same finding once, including from a later scan with a new finding id", async () => {
      await connect();
      const first = await report(alice.id);
      const created = await (await file(first, "f-csp")).json();
      const again = await file(first, "f-csp");
      expect(again.status).toBe(200);
      expect(await again.json()).toEqual({ ...created, created: false });
      const later = await report(alice.id, "https://shop.example.com/", [{ id: "f-csp-2", name: "Missing Content-Security-Policy (CSP)", severity: "high", category: "Security Headers", description: "d", evidence: "", solution: "" }]);
      expect((await file(later, "f-csp-2")).status).toBe(200);
      expect(linearCreates()).toHaveLength(1);
      expect(await ticketRows()).toHaveLength(1);
    });

    it("files one issue when the same request arrives twice at once", async () => {
      await connect();
      const reportId = await report(alice.id);
      const [a, b] = await Promise.all([file(reportId, "f-csp"), file(reportId, "f-csp")]);
      expect([a.status, b.status].sort()).toEqual([200, 201]);
      expect(linearCreates()).toHaveLength(1);
    });

    it("needs a connection first, and will not file another account's finding or a coverage notice", async () => {
      asAlice();
      const mine = await report(alice.id);
      const none = await file(mine, "f-csp");
      expect(none.status).toBe(409);
      expect((await none.json()).code).toBe("no_destination");
      await connect();
      const bobs = await report(bob.id);
      for (const [reportId, findingId] of [[bobs, "f-csp"], [mine, "nope"], [mine, "f-cov"], ["not-a-uuid", "f-csp"]] as const) {
        const res = await file(reportId, findingId);
        expect(res.status, `${reportId} ${findingId}`).toBe(404);
      }
      expect(linearCreates()).toHaveLength(0);
    });

    it.each([
      ["a key Linear no longer accepts", { status: 401, json: { errors: [{ message: "Authentication required", extensions: { type: "authentication error" } }] } }, 401, "token_rejected"],
      ["a key without access to the team", { json: { errors: [{ message: "Forbidden: team not found" }], data: null } }, 403, "no_permission"],
      ["Linear failing", { status: 500, json: {} }, 502, "linear_error"],
    ])("explains %s, and records nothing as filed", async (_label, reply, status, code) => {
      await connect();
      stub.on("POST", "linear", "/graphql", reply);
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(status);
      expect((await res.json()).code).toBe(code);
      expect(await ticketRows()).toHaveLength(0);
    });

    it("says so when the saved key can no longer be read", async () => {
      await connect();
      const { eq } = await import("drizzle-orm");
      await dbMod.db.update(dbMod.ticketDestinationsTable).set({ credentialEncrypted: "AAAA.BBBB.CCCC" }).where(eq(dbMod.ticketDestinationsTable.userId, alice.id));
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(409);
      expect((await res.json()).code).toBe("token_unreadable");
      expect(linearCreates()).toHaveLength(0);
    });

    it("stops at 100 tickets a day, counting Linear and Jira together", async () => {
      await connect();
      const reportId = await report(alice.id);
      await dbMod.db.insert(dbMod.ticketsTable).values(
        Array.from({ length: 100 }, (_, i) => ({ userId: alice.id, provider: "jira" as const, destination: "acme.atlassian.net/SEC", findingKey: `k${i}`, ticketKey: `SEC-${i}`, ticketUrl: `https://acme.atlassian.net/browse/SEC-${i}` })),
      );
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(429);
      expect((await res.json()).code).toBe("daily_limit");
      expect(linearCreates()).toHaveLength(0);
    });
  });

  describe("filing a Jira ticket", () => {
    async function connect(extra: Record<string, unknown> = {}) {
      jiraAccepts();
      asAlice();
      expect((await api("/integrations/tickets/jira", { method: "PUT", body: { ...JIRA, ...extra } })).status).toBe(200);
      stub.requests.length = 0;
    }
    const file = (reportId: string, findingId: string) => api(`/reports/${reportId}/ticket`, { method: "POST", body: { provider: "jira", findingId } });

    it("creates the ticket in the project, as a document with the evidence in a code block", async () => {
      await connect();
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(201);
      expect(await res.json()).toEqual({ created: true, provider: "jira", ticketKey: "SEC-7", ticketUrl: `${stub.jira}/browse/SEC-7` });
      const f = jiraFields();
      expect(f["project"]).toEqual({ key: "SEC" });
      expect(f["issuetype"]).toEqual({ name: "Task" });
      expect(f["summary"]).toBe("[SecScan] High: Missing Content-Security-Policy (CSP) (shop.example.com)");
      expect(f["priority"]).toEqual({ name: "High" });
      expect(f["labels"]).toEqual(["security", "secscan"]);
      expect(f["description"]).toMatchObject({ type: "doc", version: 1 });
      const doc = JSON.stringify(f["description"]);
      expect(doc).toContain("No CSP header.");
      expect(doc).toContain("codeBlock");
      expect(doc).toContain(`/report/${reportId}`);
    });

    it("uses the issue type the account chose", async () => {
      await connect({ issueType: "bug" });
      const reportId = await report(alice.id);
      await file(reportId, "f-csp");
      expect(jiraFields()["issuetype"]).toEqual({ name: "Bug" });
    });

    it("keeps secrets out of what it sends, and a mention stays plain text in the document", async () => {
      await connect();
      const reportId = await report(alice.id);
      expect((await file(reportId, "f-env")).status).toBe(201);
      const doc = JSON.stringify(jiraFields()["description"]);
      expect(doc).not.toContain("Zq8vK2mT9xW4pL7cRn5Bd3Hy");
      expect(doc).toContain("JWT_SECRET=<redacted>");
      expect(doc).not.toContain('"type":"mention"');
      expect(jiraFields()["priority"]).toEqual({ name: "Highest" });
    });

    it("files the same finding once, and a separate ticket on a different site", async () => {
      await connect();
      const a = await report(alice.id, "https://shop.example.com/");
      const b = await report(alice.id, "https://staging.example.com/");
      expect((await file(a, "f-csp")).status).toBe(201);
      expect((await file(a, "f-csp")).status).toBe(200);
      expect((await file(b, "f-csp")).status).toBe(201);
      expect(jiraCreates()).toHaveLength(2);
    });

    it("files without priority and labels when the project does not put them on its create screen", async () => {
      await connect();
      let attempts = 0;
      stub.on("POST", "jira", "/rest/api/3/issue", (r) => {
        attempts += 1;
        const fields = (JSON.parse(r.body) as { fields: Record<string, unknown> }).fields;
        if ("priority" in fields || "labels" in fields) return { status: 400, json: { errors: { priority: "Field 'priority' cannot be set.", labels: "Field 'labels' cannot be set." } } };
        return { status: 201, json: { id: "1", key: "SEC-99" } };
      });
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(201);
      expect((await res.json()).ticketKey).toBe("SEC-99");
      expect(attempts).toBe(2);
    });

    it("does not retry when the complaint is about something else", async () => {
      await connect();
      stub.on("POST", "jira", "/rest/api/3/issue", { status: 400, json: { errors: { summary: "Summary is required." } } });
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(502);
      expect(stub.requests.filter((r) => r.method === "POST")).toHaveLength(1);
      expect(await ticketRows()).toHaveLength(0);
    });

    it.each([
      ["a token Jira no longer accepts", { status: 401, json: {} }, 401, "token_rejected"],
      ["an account without the Create issues permission", { status: 403, json: {} }, 403, "no_permission"],
      ["Jira failing", { status: 500, json: {} }, 502, "jira_error"],
    ])("explains %s, and records nothing as filed", async (_label, reply, status, code) => {
      await connect();
      stub.on("POST", "jira", "/rest/api/3/issue", reply);
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(status);
      expect((await res.json()).code).toBe(code);
      expect(await ticketRows()).toHaveLength(0);
    });

    it("starts afresh when the account points at another project", async () => {
      await connect();
      const reportId = await report(alice.id);
      await file(reportId, "f-csp");
      stub.on("GET", "jira", "/rest/api/3/project/OPS", { json: { key: "OPS", issueTypes: [{ name: "Task" }] } });
      expect((await api("/integrations/tickets/jira", { method: "PUT", body: { ...JIRA, project: "ops" } })).status).toBe(200);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(201);
      expect(jiraCreates()).toHaveLength(2);
    });
  });

  describe("which findings already have a ticket", () => {
    it("maps findings to their tickets by provider, for the connected destinations only", async () => {
      linearAccepts(); jiraAccepts();
      asAlice();
      await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR });
      await api("/integrations/tickets/jira", { method: "PUT", body: JIRA });
      const reportId = await report(alice.id);
      await api(`/reports/${reportId}/ticket`, { method: "POST", body: { provider: "linear", findingId: "f-env" } });
      await api(`/reports/${reportId}/ticket`, { method: "POST", body: { provider: "jira", findingId: "f-env" } });
      await api(`/reports/${reportId}/ticket`, { method: "POST", body: { provider: "jira", findingId: "f-csp" } });
      const { tickets } = await (await api(`/reports/${reportId}/tickets`)).json();
      expect(Object.keys(tickets).sort()).toEqual(["f-csp", "f-env"]);
      expect(Object.keys(tickets["f-env"]).sort()).toEqual(["jira", "linear"]);
      expect(Object.keys(tickets["f-csp"])).toEqual(["jira"]);
      expect(tickets["f-env"].linear).toMatchObject({ ticketKey: "ENG-12" });
      // Disconnect Jira and its tickets are no longer offered as "already filed".
      await api("/integrations/tickets/jira", { method: "DELETE" });
      const after = await (await api(`/reports/${reportId}/tickets`)).json();
      expect(Object.keys(after.tickets)).toEqual(["f-env"]);
      expect(Object.keys(after.tickets["f-env"])).toEqual(["linear"]);
    });

    it("shows nothing without a destination, for another account's report, or for a malformed id", async () => {
      asAlice();
      const mine = await report(alice.id);
      expect(await (await api(`/reports/${mine}/tickets`)).json()).toEqual({ tickets: {}, destinations: [] });
      expect(await (await api(`/reports/not-a-uuid/tickets`)).json()).toEqual({ tickets: {} });
      linearAccepts();
      await api("/integrations/tickets/linear", { method: "PUT", body: LINEAR });
      await api(`/reports/${mine}/ticket`, { method: "POST", body: { provider: "linear", findingId: "f-csp" } });
      app.as(bob);
      expect(await (await api(`/reports/${mine}/tickets`)).json()).toEqual({ tickets: {}, destinations: [] });
    });
  });
});
