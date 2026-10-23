/**
 * Teams as shared viewing, over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): the real team, reports and
 * evidence routes mounted together, the real tables, and the real mailer delivering to a local mail sink
 * (lib/mailSink.testkit.ts). Most of this is about who must NOT get in.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import { randomBytes } from "node:crypto";
import { Router } from "express";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "../lib/realDb.testkit";
import { startMailSink, type MailSink } from "../lib/mailSink.testkit";

useRealDb();

type Answer = { status: number; json(): Promise<any>; arrayBuffer(): Promise<ArrayBuffer> }; // eslint-disable-line @typescript-eslint/no-explicit-any
const TOKEN_IN_URL = /\/team\/accept\?token=([0-9a-f]{64})/;

dbSuiteOf(describe)("teams: shared viewing (real Postgres, local mail)", () => {
  let dbMod: typeof import("@workspace/db");
  let app: TestApp;
  let sink: MailSink;
  let alice: { id: string; email: string };
  let bob: { id: string; email: string };
  let carol: { id: string; email: string };
  const users: string[] = [];
  const reports: string[] = [];
  let aliceReport: string;

  const call = (path: string, init: { method?: string; body?: unknown } = {}): Promise<Answer> =>
    fetch(`${app.base}${path}`, {
      method: init.method ?? "GET",
      headers: { "content-type": "application/json" },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });
  const as = (u: { id: string; email: string } | null) => app.as(u);

  async function makeReport(userId: string, targetUrl = "https://shop.example.com/") {
    const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId, userEmail: "x@example.com", targetUrl, tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
    const [r] = await dbMod.db.insert(dbMod.reportsTable).values({
      scanId: scan!.id, userId, targetUrl, tier: "deep", duration: 1,
      data: {
        summary: { totalVulnerabilities: 1, critical: 0, high: 0, medium: 1, low: 0, info: 0, riskScore: 22, grade: "B", executiveSummary: "ok" },
        vulnerabilities: [{ id: "f1", name: "Missing HSTS", severity: "medium", category: "Transport Security", description: "d", evidence: "e", solution: "s" }],
        technologies: [], targetUrl, tests: [], compliance: { frameworks: [], disclaimer: "Not a compliance verdict." },
      } as never,
    }).returning({ id: dbMod.reportsTable.id });
    reports.push(r!.id);
    return r!.id;
  }

  /** Alice invites `email`; returns the invitation token from the link the owner was given. */
  async function invite(email: string, owner = alice): Promise<string> {
    as(owner);
    const res = await call("/team/invites", { method: "POST", body: { email } });
    expect([200, 201], `invite ${email}`).toContain(res.status);
    return TOKEN_IN_URL.exec((await res.json()).inviteUrl)![1]!;
  }
  async function join(token: string, who = bob) {
    as(who);
    return call("/team/accept", { method: "POST", body: { token } });
  }
  /** The team rows of this suite's own owner (the table may hold other runs' rows). */
  async function rows() {
    const { eq } = await import("drizzle-orm");
    return dbMod.db.select().from(dbMod.teamMembersTable).where(eq(dbMod.teamMembersTable.userId, alice.id));
  }
  /** Backdates a pending invitation so it may be sent again. */
  async function ageInvites() {
    const { eq } = await import("drizzle-orm");
    await dbMod.db.update(dbMod.teamMembersTable).set({ createdAt: new Date(Date.now() - 60 * 60_000) }).where(eq(dbMod.teamMembersTable.userId, alice.id));
  }

  beforeAll(async () => {
    sink = await startMailSink();
    process.env["RESEND_API_KEY"] = "re_test_key";
    // The caps are not what this suite is about.
    process.env["TEAM_INVITES_PER_HOUR"] = "100000";
    process.env["TEAM_ACCEPTS_PER_MINUTE"] = "100000";
    process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
    dbMod = await openDb();
    const router = Router();
    router.use((await import("./team")).default);
    router.use((await import("./reports")).default);
    router.use((await import("./evidence")).default);
    app = startApp(router);
    // The address each account really has, as the database holds it (the owner's is shown to teammates).
    const person = async (tag: string) => {
      const id = await makeUser(dbMod, tag);
      const [u] = await dbMod.db.select({ email: dbMod.usersTable.email }).from(dbMod.usersTable).where((await import("drizzle-orm")).eq(dbMod.usersTable.id, id));
      return { id, email: u!.email! };
    };
    alice = await person("team-alice");
    bob = await person("team-bob");
    carol = await person("team-carol");
    users.push(alice.id, bob.id, carol.id);
    aliceReport = await makeReport(alice.id);
  }, 60_000);

  beforeEach(async () => {
    sink.clear();
    as(null);
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.teamMembersTable).where(inArray(dbMod.teamMembersTable.userId, users));
  });

  afterAll(async () => {
    app.server.close();
    await sink.stop();
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.teamMembersTable).where(inArray(dbMod.teamMembersTable.userId, users));
    await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.id, reports));
    await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
  });

  describe("every route needs a signed-in account", () => {
    it.each([
      ["GET", "/team"], ["POST", "/team/invites"], ["DELETE", "/team/members/x"], ["POST", "/team/accept"],
      ["GET", "/team/shared"], ["DELETE", "/team/shared/x"], ["GET", "/team/shared/x/reports"], ["GET", "/team/shared/x/monitors"],
    ])("%s %s", async (method, path) => {
      as(null);
      expect((await call(path, { method, ...(method === "POST" ? { body: {} } : {}) })).status).toBe(401);
    });
  });

  describe("inviting", () => {
    it("mails the invitation to the invited address, naming the owner, with a link that works only for it", async () => {
      as(alice);
      const res = await call("/team/invites", { method: "POST", body: { email: bob.email.toUpperCase() } });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body).toMatchObject({ email: bob.email, resent: false });
      expect(body.inviteUrl).toMatch(TOKEN_IN_URL);

      const mails = sink.to(bob.email);
      expect(mails).toHaveLength(1);
      expect(mails[0]!.subject).toContain(alice.email);
      expect(mails[0]!.html).toContain(body.inviteUrl);
      expect(mails[0]!.text).toContain(body.inviteUrl);
      expect(mails[0]!.html).toMatch(/not be able to run scans/);
    });

    it("stores only a hash of the invitation token", async () => {
      const token = await invite(bob.email);
      const stored = await rows();
      expect(stored).toHaveLength(1);
      expect(stored[0]!.tokenHash).toMatch(/^[0-9a-f]{64}$/);
      expect(stored[0]!.tokenHash).not.toBe(token);
      expect(JSON.stringify(stored)).not.toContain(token);
    });

    it("refuses a bad address, your own address, and an owner with no address", async () => {
      as(alice);
      for (const bad of ["", "not an email", "a@b", "x@@y.com", "<script>@x.com"]) {
        const res = await call("/team/invites", { method: "POST", body: { email: bad } });
        expect(res.status, bad).toBe(400);
        expect((await res.json()).code, bad).toBe("bad_email");
      }
      const own = await call("/team/invites", { method: "POST", body: { email: alice.email.toUpperCase() } });
      expect((await own.json()).code).toBe("own_address");
      app.as({ id: alice.id, email: null });
      expect((await (await call("/team/invites", { method: "POST", body: { email: bob.email } })).json()).code).toBe("no_owner_email");
      expect(sink.mail).toHaveLength(0);
    });

    it("will not send the same invitation again within ten minutes, and sends a new link after that; the old link stops working", async () => {
      const first = await invite(bob.email);
      const soon = await call("/team/invites", { method: "POST", body: { email: bob.email } });
      expect(soon.status).toBe(429);
      expect((await soon.json()).code).toBe("resend_too_soon");
      expect(sink.to(bob.email)).toHaveLength(1);

      await ageInvites();
      const second = await invite(bob.email);
      expect(second).not.toBe(first);
      expect(sink.to(bob.email)).toHaveLength(2);
      expect((await join(first)).status).toBe(404); // the old link is dead
      expect((await join(second)).status).toBe(200);
      expect(await rows()).toHaveLength(1);
    });

    it("says so when the person is already on the team", async () => {
      await join(await invite(bob.email));
      as(alice);
      const res = await call("/team/invites", { method: "POST", body: { email: bob.email } });
      expect(res.status).toBe(409);
      expect((await res.json()).code).toBe("already_member");
    });

    it("stops at ten people, pending invitations included", async () => {
      as(alice);
      for (let i = 0; i < 10; i++) expect((await call("/team/invites", { method: "POST", body: { email: `member${i}-${Date.now()}@example.com` } })).status).toBe(201);
      const res = await call("/team/invites", { method: "POST", body: { email: "eleventh@example.com" } });
      expect(res.status).toBe(409);
      expect((await res.json()).code).toBe("team_full");
    });
  });

  describe("accepting", () => {
    it("makes the invited account a teammate, and the link works once", async () => {
      const token = await invite(bob.email);
      expect((await join(token)).status).toBe(200);
      as(alice);
      const team = (await (await call("/team")).json()).members;
      expect(team).toHaveLength(1);
      expect(team[0]).toMatchObject({ email: bob.email, status: "active" });
      expect((await join(token)).status).toBe(404);
      const [row] = await rows();
      expect(row!.tokenHash).toBeNull();
    });

    it("works when the account's address differs from the invited one only by letter case", async () => {
      const token = await invite(bob.email);
      expect((await join(token, { ...bob, email: bob.email.toUpperCase() })).status).toBe(200);
    });

    it("refuses an account signed in with a different address, and changes nothing", async () => {
      const token = await invite(bob.email);
      const res = await join(token, carol);
      expect(res.status).toBe(403);
      expect((await res.json()).code).toBe("wrong_account");
      const [row] = await rows();
      expect(row).toMatchObject({ status: "pending", memberId: null });
      // The right person can still accept.
      expect((await join(token)).status).toBe(200);
    });

    it("refuses an account with no address", async () => {
      const token = await invite(bob.email);
      expect((await join(token, { id: bob.id, email: null as unknown as string })).status).toBe(403);
    });

    it.each(["", "short", "z".repeat(64), "A".repeat(64), "0".repeat(64), "0".repeat(65)])("refuses an invitation token that is not one (%j)", async (token) => {
      as(bob);
      expect((await call("/team/accept", { method: "POST", body: { token } })).status).toBe(404);
    });

    it("refuses a missing body", async () => {
      as(bob);
      expect((await call("/team/accept", { method: "POST", body: {} })).status).toBe(404);
    });

    it("lets one of two simultaneous attempts through", async () => {
      const token = await invite(bob.email);
      as(bob);
      const [a, b] = await Promise.all([call("/team/accept", { method: "POST", body: { token } }), call("/team/accept", { method: "POST", body: { token } })]);
      expect([a.status, b.status].sort()).toEqual([200, 404]);
    });
  });

  describe("what a teammate can read", () => {
    async function team() { await join(await invite(bob.email)); }

    it("lets the owner read as before, and a teammate read the report without the owner's account id", async () => {
      await team();
      as(alice);
      const own = await (await call(`/reports/${aliceReport}`)).json();
      expect(own).toMatchObject({ id: aliceReport, userId: alice.id, access: "owner" });

      as(bob);
      const res = await call(`/reports/${aliceReport}`);
      expect(res.status).toBe(200);
      const text = JSON.stringify(await res.json());
      expect(text).toContain(aliceReport);
      expect(text).toContain('"access":"team"');
      expect(text).not.toContain(alice.id);
    });

    it("lets a teammate download the evidence pack", async () => {
      await team();
      as(bob);
      const res = await call(`/reports/${aliceReport}/evidence-pack`);
      expect(res.status).toBe(200);
      expect((await res.arrayBuffer()).byteLength).toBeGreaterThan(500);
    });

    it("refuses someone who is not on the team, and an invitation not yet accepted", async () => {
      as(carol);
      expect((await call(`/reports/${aliceReport}`)).status).toBe(404);
      expect((await call(`/reports/${aliceReport}/evidence-pack`)).status).toBe(404);
      await invite(bob.email); // pending only
      as(bob);
      expect((await call(`/reports/${aliceReport}`)).status).toBe(404);
      expect((await call(`/reports/${aliceReport}/evidence-pack`)).status).toBe(404);
    });

    it("gives a stranger the same answer for a report that exists and one that does not", async () => {
      as(carol);
      const real = await call(`/reports/${aliceReport}`);
      const missing = await call(`/reports/00000000-0000-4000-8000-000000000000`);
      expect([real.status, await real.json()]).toEqual([missing.status, await missing.json()]);
    });

    it("does not let a team be used the other way round: the owner is not a teammate of the teammate", async () => {
      await team();
      const bobsReport = await makeReport(bob.id, "https://bob.example.com/");
      as(alice);
      expect((await call(`/reports/${bobsReport}`)).status).toBe(404);
    });

    it("ends the teammate's access on their next request when they are removed", async () => {
      await team();
      as(bob);
      expect((await call(`/reports/${aliceReport}`)).status).toBe(200);
      as(alice);
      const [row] = await rows();
      expect((await call(`/team/members/${row!.id}`, { method: "DELETE" })).status).toBe(200);
      as(bob);
      expect((await call(`/reports/${aliceReport}`)).status).toBe(404);
      expect((await call(`/reports/${aliceReport}/evidence-pack`)).status).toBe(404);
    });

    it("ends the access when the teammate leaves", async () => {
      await team();
      as(bob);
      const [t] = (await (await call("/team/shared")).json()).teams;
      expect((await call(`/team/shared/${t.id}`, { method: "DELETE" })).status).toBe(200);
      expect((await call(`/reports/${aliceReport}`)).status).toBe(404);
      expect((await (await call("/team/shared")).json()).teams).toEqual([]);
    });
  });

  describe("the teammate's lists", () => {
    it("shows who they are on the team of, and the reports, without the owner's account id", async () => {
      await join(await invite(bob.email));
      as(bob);
      const shared = await (await call("/team/shared")).json();
      expect(shared.teams).toHaveLength(1);
      expect(shared.teams[0].ownerEmail).toBe(alice.email);
      expect(JSON.stringify(shared)).not.toContain(alice.id);

      const list = await (await call(`/team/shared/${shared.teams[0].id}/reports`)).json();
      expect(list.reports.map((r: { id: string }) => r.id)).toContain(aliceReport);
      expect(list.reports[0]).toMatchObject({ grade: "B", tier: "deep" });
      expect(JSON.stringify(list)).not.toContain(alice.id);
    });

    it("will not list the reports of a team the caller is not on, whoever's membership id it is", async () => {
      await join(await invite(bob.email));
      as(alice);
      const [row] = await rows();
      for (const who of [alice, carol]) {
        as(who);
        for (const id of [row!.id, "not-a-uuid", "00000000-0000-4000-8000-000000000000"]) {
          expect((await call(`/team/shared/${id}/reports`)).status, `${who.email} ${id}`).toBe(404);
        }
      }
    });

    it("lets only the owner remove a member, and only the teammate leave", async () => {
      await join(await invite(bob.email));
      const [row] = await rows();
      as(carol);
      expect((await call(`/team/members/${row!.id}`, { method: "DELETE" })).status).toBe(404);
      expect((await call(`/team/shared/${row!.id}`, { method: "DELETE" })).status).toBe(404);
      as(alice);
      expect((await call(`/team/shared/${row!.id}`, { method: "DELETE" })).status).toBe(404); // the owner is not the teammate
      as(bob);
      expect((await call(`/team/members/${row!.id}`, { method: "DELETE" })).status).toBe(404); // the teammate is not the owner
      expect(await rows()).toHaveLength(1);
    });

    it("withdraws a pending invitation", async () => {
      const token = await invite(bob.email);
      const [row] = await rows();
      as(alice);
      expect((await call(`/team/members/${row!.id}`, { method: "DELETE" })).status).toBe(200);
      expect((await join(token)).status).toBe(404);
    });
  });

  describe("monitored sites, read-only", () => {
    const WEBHOOK = "https://hooks.slack.example/services/T000/B000/SECRETTOKENabc123";
    const subIds: string[] = [];

    async function monitor(over: Record<string, unknown> = {}) {
      const [sub] = await dbMod.db.insert(dbMod.monitorSubscriptionsTable).values({
        userId: alice.id, userEmail: alice.email, targetUrl: "https://shared-monitor.example/", webhookUrl: WEBHOOK,
        stripeSubscriptionId: "sub_secret_123", expiresAt: new Date(Date.now() + 86_400_000), lastScanAt: new Date(Date.now() - 86_400_000),
        nextScanAt: new Date(Date.now() + 6 * 86_400_000), lastReportId: aliceReport, ...over,
      }).returning({ id: dbMod.monitorSubscriptionsTable.id });
      subIds.push(sub!.id);
      return sub!.id;
    }
    async function pulse(subscriptionId: string, reachable: boolean, ms: number | null, minutesAgo: number, cert: number | null = null) {
      await dbMod.db.insert(dbMod.monitorPulseChecksTable).values({
        subscriptionId, reachable, responseTimeMs: ms, certDaysRemaining: cert, checkedAt: new Date(Date.now() - minutesAgo * 60_000),
      });
    }
    async function teamId(who = bob) {
      as(who);
      return (await (await call("/team/shared")).json()).teams[0].id as string;
    }
    async function textOf(path: string) {
      const res = await fetch(`${app.base}${path}`);
      return res.text();
    }
    afterEach(async () => {
      const { inArray } = await import("drizzle-orm");
      if (subIds.length) await dbMod.db.delete(dbMod.monitorSubscriptionsTable).where(inArray(dbMod.monitorSubscriptionsTable.id, subIds));
      subIds.length = 0;
    });

    it("a teammate sees the owner's monitored sites with grade, uptime, certificate and counts", async () => {
      const sub = await monitor();
      await pulse(sub, true, 100, 10, 40);
      await pulse(sub, true, 300, 70);
      await pulse(sub, false, null, 130);
      await join(await invite(bob.email));
      const res = await call(`/team/shared/${await teamId()}/monitors`);
      expect(res.status).toBe(200);
      const { monitors } = await res.json();
      expect(monitors).toHaveLength(1);
      expect(monitors[0]).toMatchObject({
        targetUrl: "https://shared-monitor.example/", paused: false, grade: "B", reachable: true,
        uptime24h: 66.7, medianResponseMs: 200, certDaysRemaining: 40, regressionCount: 0, cveAlertCount: 0,
      });
      expect(new Date(monitors[0].nextScanAt).getTime()).toBeGreaterThan(Date.now());
    });

    it("never carries the webhook URL, the owner's ids or email, or the billing reference", async () => {
      await monitor();
      await join(await invite(bob.email));
      const text = await textOf(`/team/shared/${await teamId()}/monitors`);
      for (const secret of ["SECRETTOKENabc123", "hooks.slack.example", "sub_secret_123", alice.id, alice.email]) expect(text).not.toContain(secret);
      expect(Object.keys(JSON.parse(text).monitors[0]).sort()).toEqual([
        "certDaysRemaining", "cveAlertCount", "grade", "lastCheckedAt", "lastScanAt", "medianResponseMs", "nextScanAt",
        "paused", "reachable", "regressionCount", "targetUrl", "uptime24h",
      ]);
    });

    it("shows a paused site as paused, with no next scan, and leaves out cancelled ones", async () => {
      await monitor({ pausedAt: new Date() });
      await monitor({ status: "cancelled", targetUrl: "https://cancelled.example/" });
      await join(await invite(bob.email));
      const { monitors } = await (await call(`/team/shared/${await teamId()}/monitors`)).json();
      expect(monitors).toHaveLength(1);
      expect(monitors[0]).toMatchObject({ paused: true, nextScanAt: null });
    });

    it("answers a site nobody has checked yet with nulls, not a guess", async () => {
      await monitor({ lastReportId: null, lastScanAt: null, nextScanAt: null });
      await join(await invite(bob.email));
      const { monitors } = await (await call(`/team/shared/${await teamId()}/monitors`)).json();
      expect(monitors[0]).toMatchObject({ grade: null, reachable: null, uptime24h: null, medianResponseMs: null, lastCheckedAt: null });
    });

    it("is for people on that team only, with one answer for every other case", async () => {
      await monitor();
      await join(await invite(bob.email));
      const id = await teamId();
      as(carol); // signed in, but not on the team
      expect((await call(`/team/shared/${id}/monitors`)).status).toBe(404);
      as(alice); // the owner has no membership of their own team
      expect((await call(`/team/shared/${id}/monitors`)).status).toBe(404);
      as(bob);
      expect((await call("/team/shared/not-a-uuid/monitors")).status).toBe(404);
      expect((await call(`/team/shared/${"0".repeat(8)}-0000-0000-0000-${"0".repeat(12)}/monitors`)).status).toBe(404);
    });

    it("ends the moment the teammate is removed", async () => {
      await monitor();
      await join(await invite(bob.email));
      const id = await teamId();
      expect((await call(`/team/shared/${id}/monitors`)).status).toBe(200);
      as(alice);
      expect((await call(`/team/members/${(await rows())[0]!.id}`, { method: "DELETE" })).status).toBe(200);
      as(bob);
      expect((await call(`/team/shared/${id}/monitors`)).status).toBe(404);
    });
  });
});
