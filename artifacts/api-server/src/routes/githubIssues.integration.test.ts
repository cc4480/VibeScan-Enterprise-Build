/**
 * File findings as GitHub issues, over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): the real routes, the
 * real tables, the real encryption, and a real local server that answers like GitHub (lib/githubStub.testkit.ts) in place
 * of api.github.com. The stub only decides what GitHub would answer and records what it was asked.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "../lib/realDb.testkit";
import { startGithubStub, useRealGithub, type GithubStub } from "../lib/githubStub.testkit";

useRealDb();

const TOKEN = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
const REPO = "acme/website";
const SECRET_LINE = "JWT_SECRET=Zq8vK2mT9xW4pL7cRn5Bd3Hy";

dbSuiteOf(describe)("GitHub issues for findings (real Postgres, local GitHub)", () => {
  let dbMod: typeof import("@workspace/db");
  let gh: GithubStub;
  let app: TestApp;
  const users: string[] = [];
  const reports: string[] = [];
  let alice: { id: string; email: string };
  let bob: { id: string; email: string };

  // The body is read as loosely typed JSON, which is what a test of a JSON API wants to poke at.
  type Answer = { status: number; json(): Promise<any>; text(): Promise<string> }; // eslint-disable-line @typescript-eslint/no-explicit-any
  const api = (path: string, init: { method?: string; body?: unknown } = {}): Promise<Answer> =>
    fetch(`${app.base}${path}`, {
      method: init.method ?? "GET",
      headers: { "content-type": "application/json" },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });
  const asAlice = () => app.as(alice);
  // This suite's own rows: the table may also hold rows other test files left behind (the account-deletion test seeds one in every table).
  async function destRows() {
    const { inArray } = await import("drizzle-orm");
    return dbMod.db.select().from(dbMod.githubIssueDestinationsTable).where(inArray(dbMod.githubIssueDestinationsTable.userId, users));
  }
  async function issueRows() {
    const { inArray } = await import("drizzle-orm");
    return dbMod.db.select().from(dbMod.githubIssuesTable).where(inArray(dbMod.githubIssuesTable.userId, users));
  }

  /** A report for `userId` holding the findings, returned with their ids. */
  async function report(userId: string, targetUrl = "https://shop.example.com/", over: Array<Record<string, unknown>> = []) {
    const vulnerabilities = [
      { id: "f-csp", name: "Missing Content-Security-Policy (CSP)", severity: "high", category: "Security Headers", description: "No CSP header.", evidence: "GET /\nNo CSP header.", solution: "Add one.", cweId: "CWE-693", wstgId: "WSTG-CONF-12" },
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

  /** GitHub accepting the token for the repository, and creating issues with increasing numbers. */
  function githubAccepts() {
    let next = 41;
    gh.on("GET", "api", `/repos/${REPO}`, { json: { full_name: REPO, has_issues: true, archived: false } });
    gh.on("POST", "api", `/repos/${REPO}/issues`, () => {
      next += 1;
      return { status: 201, json: { number: next, html_url: `https://github.com/${REPO}/issues/${next}` } };
    });
  }
  const posted = () => gh.requests.filter((r) => r.method === "POST" && r.path === `/repos/${REPO}/issues`);
  const postedBody = (i = 0) => JSON.parse(posted()[i]!.body) as { title: string; body: string; labels: string[] };

  beforeAll(async () => {
    process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
    dbMod = await openDb();
    gh = await startGithubStub();
    const router = (await import("./githubIssues")).default;
    app = startApp(router);
    alice = { id: await makeUser(dbMod, "ghi-alice"), email: "alice@example.com" };
    bob = { id: await makeUser(dbMod, "ghi-bob"), email: "bob@example.com" };
    users.push(alice.id, bob.id);
  }, 60_000);

  beforeEach(async () => {
    gh.clear();
    app.as(null);
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.githubIssuesTable).where(inArray(dbMod.githubIssuesTable.userId, users));
    await dbMod.db.delete(dbMod.githubIssueDestinationsTable).where(inArray(dbMod.githubIssueDestinationsTable.userId, users));
  });

  afterAll(async () => {
    app.server.close();
    await gh.stop();
    useRealGithub();
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.githubIssuesTable).where(inArray(dbMod.githubIssuesTable.userId, users));
    await dbMod.db.delete(dbMod.githubIssueDestinationsTable).where(inArray(dbMod.githubIssueDestinationsTable.userId, users));
    if (reports.length) await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.id, reports));
    await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
  });

  describe("the destination", () => {
    it("every route needs a signed-in account", async () => {
      expect((await api("/integrations/github-issues")).status).toBe(401);
      expect((await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO, token: TOKEN } })).status).toBe(401);
      expect((await api("/integrations/github-issues", { method: "DELETE" })).status).toBe(401);
      expect((await api(`/reports/${"0".repeat(8)}-0000-0000-0000-${"0".repeat(12)}/github-issue`, { method: "POST", body: { findingId: "x" } })).status).toBe(401);
      expect((await api(`/reports/${"0".repeat(8)}-0000-0000-0000-${"0".repeat(12)}/github-issues`)).status).toBe(401);
    });

    it("starts unconfigured", async () => {
      asAlice();
      const res = await api("/integrations/github-issues");
      expect(await res.json()).toMatchObject({ configured: false, repo: null, available: true });
    });

    it("checks the token against the repository, stores it encrypted, and never returns it", async () => {
      githubAccepts();
      asAlice();
      const res = await api("/integrations/github-issues", { method: "PUT", body: { repo: `https://github.com/${REPO}.git`, token: TOKEN } });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ configured: true, repo: REPO });
      // GitHub was asked about this repository with this token.
      const check = gh.requests.find((r) => r.path === `/repos/${REPO}`)!;
      expect(check.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
      // What is stored is ciphertext.
      const [row] = await destRows();
      expect(row!.repoFullName).toBe(REPO);
      expect(row!.tokenEncrypted).not.toContain(TOKEN);
      expect(row!.tokenEncrypted.split(".")).toHaveLength(3);
      // And it is never sent back.
      const status = await (await api("/integrations/github-issues")).text();
      expect(status).not.toContain(TOKEN);
      expect(JSON.parse(status)).toMatchObject({ configured: true, repo: REPO });
    });

    it("replaces the destination when saved again", async () => {
      githubAccepts();
      gh.on("GET", "api", "/repos/acme/other", { json: { full_name: "acme/other", has_issues: true } });
      asAlice();
      await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO, token: TOKEN } });
      await api("/integrations/github-issues", { method: "PUT", body: { repo: "acme/other", token: TOKEN } });
      expect(await (await api("/integrations/github-issues")).json()).toMatchObject({ repo: "acme/other" });
      expect(await destRows()).toHaveLength(1);
    });

    it.each([
      ["a repository that is not owner/name", { repo: "just-a-name", token: TOKEN }, 400, "bad_repo"],
      ["a repository on another host", { repo: "https://gitlab.com/acme/website", token: TOKEN }, 400, "bad_repo"],
      ["something that is not a token", { repo: REPO, token: "not a token!!" + "x".repeat(20) }, 400, "bad_token"],
    ])("refuses %s without calling GitHub", async (_label, body, status, code) => {
      asAlice();
      const res = await api("/integrations/github-issues", { method: "PUT", body });
      expect(res.status).toBe(status);
      expect((await res.json()).code).toBe(code);
      expect(gh.requests).toHaveLength(0);
    });

    it("refuses a missing body", async () => {
      asAlice();
      expect((await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO } })).status).toBe(400);
    });

    it.each([
      ["a token GitHub rejects", { status: 401, json: { message: "Bad credentials" } }, 401, "token_rejected"],
      ["a repository the token cannot see", { status: 404, json: { message: "Not Found" } }, 404, "repo_not_visible"],
      ["a repository with issues turned off", { status: 200, json: { full_name: REPO, has_issues: false } }, 409, "issues_disabled"],
      ["an archived repository", { status: 200, json: { full_name: REPO, has_issues: true, archived: true } }, 409, "archived"],
      ["GitHub failing", { status: 500, json: {} }, 502, "github_error"],
    ])("explains %s, and saves nothing", async (_label, reply, status, code) => {
      gh.on("GET", "api", `/repos/${REPO}`, reply);
      asAlice();
      const res = await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO, token: TOKEN } });
      expect(res.status).toBe(status);
      expect((await res.json()).code).toBe(code);
      expect(await destRows()).toHaveLength(0);
    });

    it("says so when GitHub cannot be reached", async () => {
      // Nothing listens on port 1: the connection is genuinely refused.
      process.env["GITHUB_API_URL"] = "http://127.0.0.1:1";
      try {
        asAlice();
        const res = await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO, token: TOKEN } });
        expect(res.status).toBe(502);
        expect((await res.json()).code).toBe("github_unreachable");
      } finally {
        await gh.stop();
        gh = await startGithubStub();
      }
    });

    it("removes the destination, and each account has its own", async () => {
      githubAccepts();
      asAlice();
      await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO, token: TOKEN } });
      app.as(bob);
      expect(await (await api("/integrations/github-issues")).json()).toMatchObject({ configured: false });
      app.as(alice);
      expect(await (await api("/integrations/github-issues", { method: "DELETE" })).json()).toEqual({ configured: false, repo: null });
      expect(await (await api("/integrations/github-issues")).json()).toMatchObject({ configured: false });
    });
  });

  describe("filing an issue", () => {
    async function connect() {
      githubAccepts();
      asAlice();
      expect((await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO, token: TOKEN } })).status).toBe(200);
      gh.requests.length = 0;
    }
    const file = (reportId: string, findingId: string) => api(`/reports/${reportId}/github-issue`, { method: "POST", body: { findingId } });

    it("creates the issue with the saved token, a title, a body and labels", async () => {
      await connect();
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(201);
      expect(await res.json()).toEqual({ created: true, issueNumber: 42, issueUrl: `https://github.com/${REPO}/issues/42`, repo: REPO });
      expect(posted()).toHaveLength(1);
      expect(posted()[0]!.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
      const sent = postedBody();
      expect(sent.title).toBe("[SecScan] High: Missing Content-Security-Policy (CSP) (shop.example.com)");
      expect(sent.labels).toEqual(["security", "secscan"]);
      expect(sent.body).toContain("No CSP header.");
      expect(sent.body).toContain(`/report/${reportId}`);
      expect(sent.body).toContain("CWE-693");
    });

    it("keeps secrets and mentions out of what it sends to GitHub", async () => {
      await connect();
      const reportId = await report(alice.id);
      expect((await file(reportId, "f-env")).status).toBe(201);
      const sent = postedBody();
      expect(sent.body).not.toContain("Zq8vK2mT9xW4pL7cRn5Bd3Hy");
      expect(sent.body).toContain("JWT_SECRET=<redacted>");
      expect(sent.body).not.toMatch(/@(?=octocat)/);
    });

    it("files the same finding once: asking again returns the issue that exists", async () => {
      await connect();
      const reportId = await report(alice.id);
      const first = await (await file(reportId, "f-csp")).json();
      const again = await file(reportId, "f-csp");
      expect(again.status).toBe(200);
      expect(await again.json()).toEqual({ ...first, created: false });
      expect(posted()).toHaveLength(1);
    });

    it("finds the issue from a later scan of the same site, whose finding has a new id", async () => {
      await connect();
      const first = await report(alice.id);
      await file(first, "f-csp");
      const later = await report(alice.id, "https://shop.example.com/", [{ id: "f-csp-2", name: "Missing Content-Security-Policy (CSP)", severity: "high", category: "Security Headers", description: "d", evidence: "", solution: "" }]);
      const res = await file(later, "f-csp-2");
      expect(res.status).toBe(200);
      expect((await res.json()).created).toBe(false);
      expect(posted()).toHaveLength(1);
    });

    it("files a separate issue for the same finding on a different site", async () => {
      await connect();
      const a = await report(alice.id, "https://shop.example.com/");
      const b = await report(alice.id, "https://staging.example.com/");
      expect((await file(a, "f-csp")).status).toBe(201);
      expect((await file(b, "f-csp")).status).toBe(201);
      expect(posted()).toHaveLength(2);
    });

    it("files one issue when the same request arrives twice at once", async () => {
      await connect();
      const reportId = await report(alice.id);
      const [a, b] = await Promise.all([file(reportId, "f-csp"), file(reportId, "f-csp")]);
      // One request filed it and the other was handed that issue, and GitHub was asked once.
      expect([a.status, b.status].sort()).toEqual([200, 201]);
      expect(posted()).toHaveLength(1);
      expect(await issueRows()).toHaveLength(1);
    });

    it("needs a connected repository first", async () => {
      asAlice();
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(409);
      expect((await res.json()).code).toBe("no_destination");
      expect(gh.requests).toHaveLength(0);
    });

    it("will not file another account's finding, or a finding that is not there, or a scan-coverage notice", async () => {
      await connect();
      const mine = await report(alice.id);
      const bobs = await report(bob.id);
      for (const [reportId, findingId] of [[bobs, "f-csp"], [mine, "nope"], [mine, "f-cov"], ["not-a-uuid", "f-csp"]] as const) {
        const res = await file(reportId, findingId);
        expect(res.status, `${reportId} ${findingId}`).toBe(404);
        expect((await res.json()).code).toBe("finding_not_found");
      }
      expect(posted()).toHaveLength(0);
    });

    it.each([
      ["a token GitHub no longer accepts", { status: 401, json: { message: "Bad credentials" } }, 401, "token_rejected"],
      ["a token without Issues permission", { status: 403, json: { message: "Resource not accessible by personal access token" } }, 403, "no_permission"],
      ["issues turned off since", { status: 410, json: { message: "Issues are disabled" } }, 409, "issues_disabled"],
      ["GitHub failing", { status: 500, json: {} }, 502, "github_error"],
    ])("explains %s, and records nothing as filed", async (_label, reply, status, code) => {
      await connect();
      gh.on("POST", "api", `/repos/${REPO}/issues`, reply);
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(status);
      expect((await res.json()).code).toBe(code);
      expect(await issueRows()).toHaveLength(0);
    });

    it("says so when the saved token can no longer be read, rather than failing obscurely", async () => {
      await connect();
      const { eq } = await import("drizzle-orm");
      await dbMod.db.update(dbMod.githubIssueDestinationsTable).set({ tokenEncrypted: "AAAA.BBBB.CCCC" }).where(eq(dbMod.githubIssueDestinationsTable.userId, alice.id));
      const reportId = await report(alice.id);
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(409);
      expect((await res.json()).code).toBe("token_unreadable");
      expect(posted()).toHaveLength(0);
    });

    it("stops at 100 issues a day", async () => {
      await connect();
      const reportId = await report(alice.id);
      await dbMod.db.insert(dbMod.githubIssuesTable).values(
        Array.from({ length: 100 }, (_, i) => ({ userId: alice.id, repoFullName: REPO, findingKey: `k${i}`, issueNumber: i + 1, issueUrl: `https://github.com/${REPO}/issues/${i + 1}` })),
      );
      const res = await file(reportId, "f-csp");
      expect(res.status).toBe(429);
      expect((await res.json()).code).toBe("daily_limit");
      expect(posted()).toHaveLength(0);
    });
  });

  describe("which findings already have an issue", () => {
    it("maps the findings of a report to their issues, for the connected repository only", async () => {
      githubAccepts();
      asAlice();
      await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO, token: TOKEN } });
      const reportId = await report(alice.id);
      await api(`/reports/${reportId}/github-issue`, { method: "POST", body: { findingId: "f-env" } });
      const { issues } = await (await api(`/reports/${reportId}/github-issues`)).json();
      expect(Object.keys(issues)).toEqual(["f-env"]);
      expect(issues["f-env"]).toMatchObject({ issueNumber: 42, issueUrl: `https://github.com/${REPO}/issues/42` });
    });

    it("shows nothing without a destination, for another account's report, or for a malformed id", async () => {
      asAlice();
      const mine = await report(alice.id);
      expect(await (await api(`/reports/${mine}/github-issues`)).json()).toEqual({ issues: {}, destination: { configured: false, repo: null, available: true } });
      expect(await (await api(`/reports/not-a-uuid/github-issues`)).json()).toEqual({ issues: {} });
      githubAccepts();
      await api("/integrations/github-issues", { method: "PUT", body: { repo: REPO, token: TOKEN } });
      await api(`/reports/${mine}/github-issue`, { method: "POST", body: { findingId: "f-csp" } });
      app.as(bob);
      expect(await (await api(`/reports/${mine}/github-issues`)).json()).toEqual({ issues: {}, destination: null });
    });
  });
});
