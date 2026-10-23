/**
 * The public REST API under /api/v1, over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): real API
 * tokens and users, the real scan-launch handler (limiters, free-trial charge, SSRF guard, job queue), real scan and
 * report rows, and the real comparison with the previous scan. Each test uses an account and a client address of
 * its own, so one test's scans never count against another's allowance.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, startApp, uniqueEmail, type TestApp } from "../lib/realDb.testkit";

useRealDb();
delete process.env["FREE_TRIAL_SCAN_LIMIT"]; // the default of three free scans

const OTHER_ID = "22222222-2222-4222-8222-222222222222";
const CSP = "Missing Content-Security-Policy (CSP)";
const headersRan = { group: "g", name: "response headers and cookies", status: "ran", findings: 0, durationMs: 1 };

// The API answers JSON; the tests read it loosely.
type Res = Omit<Response, "json"> & { json(): Promise<any> };

dbSuiteOf(describe)("/api/v1 (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let app: TestApp;
  let apiTokens: typeof import("../lib/apiTokens");
  let savedCf: string | undefined;
  const users: string[] = [];
  const scanIds: string[] = [];
  let n = 0;

  const ip = () => `198.51.${Math.floor(++n / 250)}.${(n % 250) + 1}`;
  /** A user holding a live token of the given scope, calling from an address of their own. */
  async function account(scope: "api" | "mcp" = "api") {
    const email = uniqueEmail("v1");
    const [u] = await dbMod.db.insert(dbMod.usersTable).values({ email, firstName: "Dev" }).returning({ id: dbMod.usersTable.id });
    users.push(u!.id);
    const g = apiTokens.generateToken();
    await dbMod.db.insert(dbMod.apiTokensTable).values({ userId: u!.id, name: "t", tokenHash: g.hash, prefix: g.prefix, scope });
    const headers = { authorization: `Bearer ${g.token}`, "x-forwarded-for": ip() };
    return { id: u!.id, email, headers };
  }
  const get = (path: string, headers: Record<string, string>) => fetch(app.base + path, { headers }) as Promise<Res>;
  const post = (path: string, body: unknown, headers: Record<string, string>) =>
    fetch(app.base + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) }) as Promise<Res>;
  const target = (name: string) => `http://127.0.0.1:9/${name}-${Date.now()}-${++n}`;

  /** A scan row (and, for a finished one, its report) belonging to `userId`. */
  async function scan(userId: string, opts: { status?: string; data?: unknown; targetUrl?: string; daysAgo?: number } = {}) {
    const at = new Date(Date.now() - (opts.daysAgo ?? 0) * 86_400_000);
    const targetUrl = opts.targetUrl ?? "https://a.example/";
    const status = opts.status ?? "complete";
    const [s] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId, userEmail: uniqueEmail("scan"), targetUrl, tier: "deep", status: status as never, createdAt: at, completedAt: status === "complete" ? at : null })
      .returning({ id: dbMod.scansTable.id });
    scanIds.push(s!.id);
    if (opts.data !== undefined) {
      await dbMod.db.insert(dbMod.reportsTable).values({ scanId: s!.id, userId, targetUrl, tier: "deep", scannedAt: at, duration: 1, data: opts.data as never });
    }
    return s!.id;
  }
  const finishedData = {
    summary: { grade: "B", riskScore: 21 },
    vulnerabilities: [{ severity: "high" }, { severity: "low" }, { severity: "low" }],
    tests: [{ group: "g", name: "a", status: "ran", findings: 1, durationMs: 1 }, { group: "g", name: "b", status: "skipped", findings: 0, durationMs: 0 }],
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    apiTokens = await import("../lib/apiTokens");
    savedCf = process.env["BEHIND_CLOUDFLARE"];
    process.env["BEHIND_CLOUDFLARE"] = "true"; // the client address is then read from X-Forwarded-For, as in production
    const { default: v1 } = await import("./v1");
    app = startApp(v1 as never, { json: true });
  }, 60_000);

  afterAll(async () => {
    app?.server.close();
    if (savedCf === undefined) delete process.env["BEHIND_CLOUDFLARE"];
    else process.env["BEHIND_CLOUDFLARE"] = savedCf;
    const { inArray } = await import("drizzle-orm");
    if (users.length) {
      await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.userId, users));
      await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
      await dbMod.db.delete(dbMod.apiTokensTable).where(inArray(dbMod.apiTokensTable.userId, users));
      await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
    }
    await dbMod?.pool?.end?.();
  });

  describe("authentication", () => {
    it("refuses a request with no token, in the API's own error shape", async () => {
      const res = await get("/v1/me", {});
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toContain("Bearer");
      expect((await res.json()).error.code).toBe("unauthorized");
    });

    it("asks for the api scope, so a valid MCP token is refused", async () => {
      const mcp = await account("mcp");
      expect((await get("/v1/me", mcp.headers)).status).toBe(401);
    });

    it("refuses a token that was never issued", async () => {
      expect((await get("/v1/me", { authorization: "Bearer ssk_neverissued" })).status).toBe(401);
    });

    it("accepts an api token", async () => {
      const a = await account();
      const res = await get("/v1/me", a.headers);
      expect(res.status).toBe(200);
      expect((await res.json()).email).toBe(a.email);
    });

    it("serves the OpenAPI document without a token", async () => {
      const res = await get("/v1/openapi.json", {});
      expect(res.status).toBe(200);
      expect((await res.json()).openapi).toBe("3.1.0");
    });
  });

  describe("POST /v1/scans", () => {
    it("queues a real scan and returns its id", async () => {
      const a = await account();
      const url = target("queue");
      const res = await post("/v1/scans", { url }, a.headers);
      expect(res.status).toBe(202);
      const body = await res.json();
      expect(body).toMatchObject({ status: "queued", paidWith: "free" });
      scanIds.push(body.id);
      const [row] = await dbMod.db.select().from(dbMod.scansTable).where(eq(dbMod.scansTable.id, body.id));
      expect(row).toMatchObject({ userId: a.id, targetUrl: url });
    });

    it("stores an optional GitHub repository on the scan, and none when it is absent", async () => {
      const a = await account();
      const withRepo = await (await post("/v1/scans", { url: target("repo"), githubRepo: "https://github.com/acme/shop" }, a.headers)).json();
      const without = await (await post("/v1/scans", { url: target("norepo") }, a.headers)).json();
      scanIds.push(withRepo.id, without.id);
      const rows = await dbMod.db.select().from(dbMod.scansTable).where(eq(dbMod.scansTable.userId, a.id));
      expect(rows.find((r) => r.id === withRepo.id)?.githubRepoUrl).toBe("https://github.com/acme/shop");
      expect(rows.find((r) => r.id === without.id)?.githubRepoUrl ?? null).toBeNull();
    });

    it("rejects a body without a url", async () => {
      const a = await account();
      for (const bad of [{}, { url: "" }, { url: 5 }]) {
        const res = await post("/v1/scans", bad, a.headers);
        expect(res.status).toBe(400);
        expect((await res.json()).error.code).toBe("invalid_request");
      }
    });

    it("passes the website's refusals through with stable codes: free scans used up, then the rate limit", async () => {
      const a = await account();
      for (let i = 0; i < 3; i++) {
        const ok = await post("/v1/scans", { url: target(`free${i}`) }, a.headers);
        expect(ok.status).toBe(202);
        scanIds.push((await ok.json()).id);
      }
      // The fourth is past the three free scans; the real handler refuses it.
      const used = await post("/v1/scans", { url: target("fourth") }, a.headers);
      expect(used.status).toBe(403);
      expect((await used.json()).error.code).toBe("forbidden");
      await post("/v1/scans", { url: target("fifth") }, a.headers);
      // The sixth within the hour hits the per-account limit of five.
      const limited = await post("/v1/scans", { url: target("sixth") }, a.headers);
      expect(limited.status).toBe(429);
      expect((await limited.json()).error.code).toBe("rate_limited");
    });
  });

  describe("GET /v1/scans/:id", () => {
    it("returns a short summary of a finished scan", async () => {
      const a = await account();
      const id = await scan(a.id, { data: finishedData });
      const body = await (await get(`/v1/scans/${id}`, a.headers)).json();
      expect(body).toMatchObject({
        id, status: "complete", grade: "B", riskScore: 21,
        findings: { high: 1, low: 2, total: 3 },
        coverage: { ran: 1, skipped: 1, failed: 0, total: 2 },
      });
      expect(body.links.report).toContain(`/scans/${id}/report`);
    });

    it("adds counts of what changed since the last scan, and the full lists on the report", async () => {
      const a = await account();
      const url = target("changes");
      const other = { name: "Missing Referrer-Policy Header", severity: "low", category: "HTTP Security", evidence: "" };
      const csp = { name: CSP, severity: "high", category: "HTTP Security", evidence: "" };
      await scan(a.id, { targetUrl: url, daysAgo: 3, data: { summary: { grade: "C", riskScore: 40 }, vulnerabilities: [csp, other], tests: [headersRan] } });
      const id = await scan(a.id, { targetUrl: url, data: { summary: { grade: "B", riskScore: 21 }, vulnerabilities: [other], tests: [headersRan] } });
      const status = await (await get(`/v1/scans/${id}`, a.headers)).json();
      expect(status.changes).toMatchObject({ new: 0, fixed: 1, notRechecked: 0, unchanged: 1 });
      const report = await (await get(`/v1/scans/${id}/report`, a.headers)).json();
      expect(report.changes.fixed.map((f: { name: string }) => f.name)).toEqual([CSP]);
    });

    it("leaves changes out for a first scan", async () => {
      const a = await account();
      const id = await scan(a.id, { targetUrl: target("first"), data: finishedData });
      expect((await (await get(`/v1/scans/${id}`, a.headers)).json()).changes).toBeUndefined();
    });

    it("returns only the status while a scan is running", async () => {
      const a = await account();
      const id = await scan(a.id, { status: "scanning" });
      const body = await (await get(`/v1/scans/${id}`, a.headers)).json();
      expect(body.status).toBe("scanning");
      expect(body.grade).toBeUndefined();
    });

    it("answers 404, never 403, for someone else's scan and for a malformed id", async () => {
      const mine = await account();
      const theirs = await account();
      const id = await scan(theirs.id, { data: finishedData });
      expect((await get(`/v1/scans/${id}`, mine.headers)).status).toBe(404);
      expect((await get(`/v1/scans/${OTHER_ID}`, mine.headers)).status).toBe(404);
      expect((await get("/v1/scans/not-a-uuid", mine.headers)).status).toBe(404);
    });

    it("does not wait when the scan is already finished, even if asked to", async () => {
      const a = await account();
      const id = await scan(a.id, { data: finishedData });
      const started = Date.now();
      const res = await get(`/v1/scans/${id}?wait=60`, a.headers);
      expect(res.status).toBe(200);
      expect(Date.now() - started).toBeLessThan(2000);
    });
  });

  describe("GET /v1/scans/:id/report", () => {
    it("returns the full report for a finished scan", async () => {
      const a = await account();
      const id = await scan(a.id, { data: finishedData, targetUrl: "https://a.example/" });
      const body = await (await get(`/v1/scans/${id}/report`, a.headers)).json();
      expect(body.report.summary.grade).toBe("B");
      expect(body.url).toBe("https://a.example/");
    });

    it("says not_ready (409) for an unfinished scan", async () => {
      const a = await account();
      const id = await scan(a.id, { status: "queued" });
      const res = await get(`/v1/scans/${id}/report`, a.headers);
      expect(res.status).toBe(409);
      expect((await res.json()).error.code).toBe("not_ready");
    });

    it("404s another user's scan", async () => {
      const mine = await account();
      const id = await scan((await account()).id, { data: finishedData });
      expect((await get(`/v1/scans/${id}/report`, mine.headers)).status).toBe(404);
    });
  });

  describe("GET /v1/scans/:id/sarif", () => {
    it("returns the findings as a SARIF log", async () => {
      const a = await account();
      const id = await scan(a.id, {
        data: { vulnerabilities: [{ name: "Open Redirect Vulnerability", severity: "medium", description: "d", evidence: "GET https://a.example/r", solution: "s" }] },
      });
      const res = await get(`/v1/scans/${id}/sarif`, a.headers);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("sarif+json");
      const log = await res.json();
      expect(log.version).toBe("2.1.0");
      expect(log.runs[0].results).toHaveLength(1);
    });

    it("says not_ready for an unfinished scan and 404s someone else's", async () => {
      const a = await account();
      expect((await get(`/v1/scans/${await scan(a.id, { status: "scanning" })}/sarif`, a.headers)).status).toBe(409);
      const theirs = await scan((await account()).id, { data: finishedData });
      expect((await get(`/v1/scans/${theirs}/sarif`, a.headers)).status).toBe(404);
    });
  });

  describe("the rest of /v1", () => {
    it("lists the caller's recent scans and no one else's", async () => {
      const a = await account();
      const mine = await scan(a.id, { data: finishedData });
      await scan((await account()).id, { data: finishedData });
      const body = await (await get("/v1/scans", a.headers)).json();
      expect(body.scans.map((s: { id: string }) => s.id)).toEqual([mine]);
    });

    it("answers an unknown path in the API's own JSON error shape", async () => {
      const a = await account();
      const res = await get("/v1/nope", a.headers);
      expect(res.status).toBe(404);
      expect((await res.json()).error.code).toBe("not_found");
    });
  });
});

describe("the spec describes exactly the routes that exist", () => {
  it("has a spec entry for every route and a route for every spec entry", async () => {
    const { default: v1 } = await import("./v1");
    const { API_V1_SPEC } = await import("../lib/apiV1Spec");
    type Layer = { route?: { path: string; methods: Record<string, boolean> } };
    const routes = new Set<string>();
    for (const layer of (v1 as unknown as { stack: Layer[] }).stack) {
      if (!layer.route) continue;
      for (const method of Object.keys(layer.route.methods)) routes.add(`${method} ${layer.route.path.replace(/^\/v1/, "").replace(/:(\w+)/g, "{$1}")}`);
    }
    const documented = new Set<string>();
    for (const [path, ops] of Object.entries(API_V1_SPEC.paths)) for (const method of Object.keys(ops)) documented.add(`${method} ${path}`);
    expect([...routes].sort()).toEqual([...documented].sort());
  });
});
