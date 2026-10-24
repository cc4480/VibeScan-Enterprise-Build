/**
 * Team roles over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): the real routes, tables and encryption, and a
 * real local server that answers like Linear (lib/ticketStub.testkit.ts). A viewer reads; an editor can also pause and resume
 * the owner's monitors and file tickets from the owner's reports; and nobody on a team can do anything else that is the owner's.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { Router } from "express";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "../lib/realDb.testkit";
import { startTicketStub, useRealTickets, type TicketStub } from "../lib/ticketStub.testkit";

useRealDb();

const LINEAR_KEY = "lin_api_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4";
const SITE = "https://roles.example.com/";

dbSuiteOf(describe)("team roles: viewer and editor (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let stub: TicketStub;
  let app: TestApp;
  const users: string[] = [];
  const reports: string[] = [];
  let owner: { id: string; email: string };
  let editor: { id: string; email: string };
  let viewer: { id: string; email: string };
  let outsider: { id: string; email: string };
  let editorMembership: string;
  let viewerMembership: string;
  let subId: string;
  let reportId: string;

  type Answer = { status: number; json(): Promise<any>; text(): Promise<string> }; // eslint-disable-line @typescript-eslint/no-explicit-any
  const api = (path: string, init: { method?: string; body?: unknown } = {}): Promise<Answer> =>
    fetch(`${app.base}${path}`, { method: init.method ?? "GET", headers: { "content-type": "application/json" }, ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}) });
  const linearCreates = () => stub.requests.filter((r) => r.host === "linear" && r.body.includes("issueCreate"));

  async function ticketRows() {
    const { inArray } = await import("drizzle-orm");
    return dbMod.db.select().from(dbMod.ticketsTable).where(inArray(dbMod.ticketsTable.userId, users));
  }
  async function pausedAt() {
    const { eq } = await import("drizzle-orm");
    const [s] = await dbMod.db.select({ p: dbMod.monitorSubscriptionsTable.pausedAt }).from(dbMod.monitorSubscriptionsTable).where(eq(dbMod.monitorSubscriptionsTable.id, subId));
    return s!.p;
  }
  async function member(ownerId: string, who: { id: string; email: string }, role: "viewer" | "editor") {
    const [m] = await dbMod.db.insert(dbMod.teamMembersTable).values({ userId: ownerId, memberId: who.id, invitedEmail: who.email, status: "active", role, acceptedAt: new Date() }).returning({ id: dbMod.teamMembersTable.id });
    return m!.id;
  }

  beforeAll(async () => {
    process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
    dbMod = await openDb();
    stub = await startTicketStub();
    const router = Router();
    for (const f of ["team", "monitorControls", "tickets", "githubIssues", "reports"]) router.use((await import(`./${f}`)).default);
    app = startApp(router);

    const mk = async (tag: string) => ({ id: await makeUser(dbMod, tag), email: `${tag}@example.com` });
    owner = await mk("role-owner"); editor = await mk("role-editor"); viewer = await mk("role-viewer"); outsider = await mk("role-outsider");
    users.push(owner.id, editor.id, viewer.id, outsider.id);
    editorMembership = await member(owner.id, editor, "editor");
    viewerMembership = await member(owner.id, viewer, "viewer");

    stub.on("POST", "linear", "/graphql", (r) => {
      const { query } = JSON.parse(r.body) as { query: string };
      if (query.includes("teams(")) return { json: { data: { teams: { nodes: [{ id: "team-id", key: "ENG" }] } } } };
      return { json: { data: { issueCreate: { success: true, issue: { identifier: "ENG-77", url: "https://linear.app/acme/issue/ENG-77/x" } } } } };
    });
    const { saveDestination } = await import("../lib/tickets");
    expect((await saveDestination(owner.id, { provider: "linear", team: "eng", apiKey: LINEAR_KEY })).ok).toBe(true);

    const [sub] = await dbMod.db.insert(dbMod.monitorSubscriptionsTable).values({ userId: owner.id, userEmail: "", targetUrl: SITE, expiresAt: new Date(Date.now() + 86_400_000) }).returning({ id: dbMod.monitorSubscriptionsTable.id });
    subId = sub!.id;
    const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId: owner.id, userEmail: "x@example.com", targetUrl: SITE, tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
    const data = {
      summary: { totalVulnerabilities: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0, riskScore: 50, grade: "C", executiveSummary: "One." }, technologies: [], targetUrl: SITE,
      vulnerabilities: [{ id: "f1", name: "Missing CSP", severity: "high", category: "Security Headers", description: "No CSP.", evidence: "GET /", solution: "Add one." }], tests: [],
    };
    const [r] = await dbMod.db.insert(dbMod.reportsTable).values({ scanId: scan!.id, userId: owner.id, targetUrl: SITE, tier: "deep", duration: 1, data: data as never }).returning({ id: dbMod.reportsTable.id });
    reportId = r!.id;
    reports.push(reportId);
  }, 60_000);

  afterAll(async () => {
    app.server.close();
    await stub.stop();
    useRealTickets();
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.ticketsTable).where(inArray(dbMod.ticketsTable.userId, users));
    await dbMod.db.delete(dbMod.ticketDestinationsTable).where(inArray(dbMod.ticketDestinationsTable.userId, users));
    await dbMod.db.delete(dbMod.teamMembersTable).where(inArray(dbMod.teamMembersTable.userId, users));
    await dbMod.db.delete(dbMod.monitorSubscriptionsTable).where(inArray(dbMod.monitorSubscriptionsTable.userId, users));
    await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.id, reports));
    await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
  });

  describe("choosing a role", () => {
    it("an invitation is for a viewer unless the owner says editor, and the list says which", async () => {
      app.as(owner);
      const a = await api("/team/invites", { method: "POST", body: { email: "plain@example.com" } });
      const b = await api("/team/invites", { method: "POST", body: { email: "boss@example.com", role: "editor" } });
      expect([a.status, b.status]).toEqual([201, 201]);
      const list = (await (await api("/team")).json()).members as Array<{ email: string; role: string }>;
      expect(list.find((m) => m.email === "plain@example.com")!.role).toBe("viewer");
      expect(list.find((m) => m.email === "boss@example.com")!.role).toBe("editor");
      expect((await api("/team/invites", { method: "POST", body: { email: "x@example.com", role: "admin" } })).status).toBe(400);
      const { inArray } = await import("drizzle-orm");
      await dbMod.db.delete(dbMod.teamMembersTable).where(inArray(dbMod.teamMembersTable.invitedEmail, ["plain@example.com", "boss@example.com"]));
    });

    it("only the owner changes a role, and only for their own team", async () => {
      app.as(null);
      expect((await api(`/team/members/${viewerMembership}/role`, { method: "PATCH", body: { role: "editor" } })).status).toBe(401);
      for (const who of [editor, viewer, outsider]) {
        app.as(who);
        expect((await api(`/team/members/${viewerMembership}/role`, { method: "PATCH", body: { role: "editor" } })).status, who.email).toBe(404);
      }
      app.as(owner);
      expect((await api(`/team/members/${viewerMembership}/role`, { method: "PATCH", body: { role: "admin" } })).status).toBe(400);
      expect((await api("/team/members/not-a-uuid/role", { method: "PATCH", body: { role: "editor" } })).status).toBe(404);
      const { eq } = await import("drizzle-orm");
      const [row] = await dbMod.db.select().from(dbMod.teamMembersTable).where(eq(dbMod.teamMembersTable.id, viewerMembership));
      expect(row!.role).toBe("viewer");
    });

    it("the teammate is told their own role, and a report says what they may do", async () => {
      app.as(editor);
      const shared = (await (await api("/team/shared")).json()).teams as Array<{ id: string; role: string }>;
      expect(shared.find((t) => t.id === editorMembership)!.role).toBe("editor");
      expect((await (await api(`/reports/${reportId}`)).json())).toMatchObject({ access: "team", role: "editor" });
      app.as(viewer);
      expect((await (await api(`/reports/${reportId}`)).json())).toMatchObject({ access: "team", role: "viewer" });
      app.as(owner);
      const own = await (await api(`/reports/${reportId}`)).json();
      expect(own.access).toBe("owner");
      expect(own.role).toBeUndefined();
    });
  });

  describe("pausing the owner's monitors", () => {
    it("an editor can pause and resume, as the owner can", async () => {
      app.as(editor);
      expect((await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: true } })).status).toBe(200);
      expect(await pausedAt()).not.toBeNull();
      expect((await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: false } })).status).toBe(200);
      expect(await pausedAt()).toBeNull();
      app.as(owner);
      expect((await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: true } })).status).toBe(200);
      await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: false } });
    });

    it("a viewer, an outsider and a signed-out caller cannot, and are told the site does not exist", async () => {
      for (const who of [viewer, outsider]) {
        app.as(who);
        const res = await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: true } });
        expect(res.status, who.email).toBe(404);
      }
      app.as(null);
      expect((await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: true } })).status).toBe(401);
      expect(await pausedAt()).toBeNull();
    });

    it("an editor cannot change the rescan interval, which stays the owner's", async () => {
      app.as(editor);
      const res = await api(`/monitor/subscriptions/${subId}/interval`, { method: "PATCH", body: { days: 30 } });
      expect(res.status).toBe(404);
    });

    it("the site list gives an editor the id they need and a viewer nothing of the kind", async () => {
      app.as(editor);
      const forEditor = (await (await api(`/team/shared/${editorMembership}/monitors`)).json()).monitors;
      expect(forEditor[0].id).toBe(subId);
      app.as(viewer);
      const forViewer = (await (await api(`/team/shared/${viewerMembership}/monitors`)).json()).monitors;
      expect(forViewer[0].id).toBeUndefined();
      expect(JSON.stringify(forViewer)).not.toContain(subId);
    });
  });

  describe("filing tickets from the owner's report", () => {
    const file = (id = reportId) => api(`/reports/${id}/ticket`, { method: "POST", body: { provider: "linear", findingId: "f1" } });

    it("an editor files through the owner's saved destination, and the ticket belongs to the owner", async () => {
      stub.requests.length = 0;
      app.as(editor);
      const res = await file();
      expect(res.status).toBe(201);
      expect(await res.json()).toMatchObject({ created: true, ticketKey: "ENG-77" });
      // Sent with the owner's key, recorded under the owner.
      expect(linearCreates()).toHaveLength(1);
      expect(linearCreates()[0]!.headers["authorization"]).toBe(LINEAR_KEY);
      const rows = await ticketRows();
      expect(rows).toHaveLength(1);
      expect(rows[0]!.userId).toBe(owner.id);
      // The owner sees it, and filing it again (from either) returns the same ticket.
      app.as(owner);
      expect((await (await api(`/reports/${reportId}/tickets`)).json()).tickets.f1.linear.ticketKey).toBe("ENG-77");
      expect((await file()).status).toBe(200);
      expect(linearCreates()).toHaveLength(1);
    });

    it("an editor is told where tickets go, and never given the credential", async () => {
      app.as(editor);
      const text = await (await api(`/reports/${reportId}/tickets`)).text();
      expect(JSON.parse(text).destinations).toEqual([{ provider: "linear", target: "ENG", site: null, accountEmail: null, issueType: null, autoFile: false, autoMinSeverity: "high" }]);
      expect(text).not.toContain(LINEAR_KEY);
      expect(text).not.toContain(owner.id);
    });

    it("a viewer and an outsider cannot file, and nothing reaches Linear", async () => {
      stub.requests.length = 0;
      const { inArray } = await import("drizzle-orm");
      await dbMod.db.delete(dbMod.ticketsTable).where(inArray(dbMod.ticketsTable.userId, users));
      for (const who of [viewer, outsider]) {
        app.as(who);
        const res = await file();
        expect(res.status, who.email).toBe(404);
        expect((await (await api(`/reports/${reportId}/tickets`)).json())).toEqual({ tickets: {}, destinations: [] });
      }
      expect(stub.requests).toHaveLength(0);
      expect(await ticketRows()).toHaveLength(0);
    });

    it("an editor's own connections are their own: they cannot read or change the owner's", async () => {
      app.as(editor);
      expect((await (await api("/integrations/tickets")).json()).destinations).toEqual([]);
      await api("/integrations/tickets/linear", { method: "DELETE" });
      const { getDestination } = await import("../lib/tickets");
      expect(await getDestination(owner.id, "linear")).not.toBeNull();
    });

    it("an editor cannot manage the owner's team", async () => {
      app.as(editor);
      expect((await api(`/team/members/${viewerMembership}`, { method: "DELETE" })).status).toBe(404);
      expect((await (await api("/team")).json()).members).toEqual([]); // their own, empty
      const { eq } = await import("drizzle-orm");
      expect(await dbMod.db.select().from(dbMod.teamMembersTable).where(eq(dbMod.teamMembersTable.id, viewerMembership))).toHaveLength(1);
    });
  });

  describe("when the role changes or the teammate goes", () => {
    it("demoting an editor stops filing and pausing at once, and removing them stops reading too", async () => {
      app.as(owner);
      expect((await api(`/team/members/${editorMembership}/role`, { method: "PATCH", body: { role: "viewer" } })).status).toBe(200);
      app.as(editor);
      expect((await api(`/reports/${reportId}/ticket`, { method: "POST", body: { provider: "linear", findingId: "f1" } })).status).toBe(404);
      expect((await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: true } })).status).toBe(404);
      expect((await api(`/reports/${reportId}`)).status).toBe(200); // still reads

      app.as(owner);
      await api(`/team/members/${editorMembership}/role`, { method: "PATCH", body: { role: "editor" } });
      app.as(editor);
      expect((await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: false } })).status).toBe(200);

      app.as(owner);
      expect((await api(`/team/members/${editorMembership}`, { method: "DELETE" })).status).toBe(200);
      app.as(editor);
      expect((await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: true } })).status).toBe(404);
      expect((await api(`/reports/${reportId}`)).status).toBe(404);
    });

    it("a pending invitation grants nothing, whatever its role", async () => {
      const ghost = { id: await makeUser(dbMod, "role-ghost"), email: "role-ghost@example.com" };
      users.push(ghost.id);
      await dbMod.db.insert(dbMod.teamMembersTable).values({ userId: owner.id, invitedEmail: ghost.email, tokenHash: "f".repeat(64), status: "pending", role: "editor" });
      app.as(ghost);
      expect((await api(`/monitor/subscriptions/${subId}/pause`, { method: "PATCH", body: { paused: true } })).status).toBe(404);
      expect((await api(`/reports/${reportId}/ticket`, { method: "POST", body: { provider: "linear", findingId: "f1" } })).status).toBe(404);
    });
  });
});
