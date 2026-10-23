/**
 * The evidence pack download and the public signature check, over real HTTP against a REAL Postgres
 * (BILLING_TEST_DATABASE_URL): the real routes, the real reports table, the real signing.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "../lib/realDb.testkit";
import { readZip } from "../lib/zipReader.testkit";

useRealDb();

const MISSING = "00000000-0000-4000-8000-000000000000";

dbSuiteOf(describe)("evidence packs (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let app: TestApp;
  const users: string[] = [];
  const reportIds: string[] = [];
  let alice: { id: string; email: string };
  let bob: { id: string; email: string };
  let aliceReport: string;

  async function makeReport(userId: string, targetUrl = "https://shop.example.com/") {
    const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId, userEmail: "x@example.com", targetUrl, tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
    const [r] = await dbMod.db.insert(dbMod.reportsTable).values({
      scanId: scan!.id, userId, targetUrl, tier: "deep", duration: 1,
      data: {
        summary: { grade: "B", riskScore: 22 },
        vulnerabilities: [{ id: "f1", name: "Missing HSTS", severity: "medium", category: "Transport Security", description: "No HSTS header.", evidence: "GET /", solution: "Add it." }],
        tests: [{ group: "HTTP probes", name: "security headers", status: "ran", findings: 1, durationMs: 4 }],
      } as never,
    }).returning({ id: dbMod.reportsTable.id });
    reportIds.push(r!.id);
    return r!.id;
  }
  // Responses are read raw: the pack is bytes, not JSON.
  const get = (path: string) => fetch(`${app.base}${path}`);
  const verify = (body: unknown) => fetch(`${app.base}/evidence/verify`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

  beforeAll(async () => {
    process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
    dbMod = await openDb();
    const router = (await import("./evidence")).default;
    app = startApp(router);
    alice = { id: await makeUser(dbMod, "ev-alice"), email: "alice@example.com" };
    bob = { id: await makeUser(dbMod, "ev-bob"), email: "bob@example.com" };
    users.push(alice.id, bob.id);
    aliceReport = await makeReport(alice.id);
  }, 60_000);

  afterAll(async () => {
    app.server.close();
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.id, reportIds));
    await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
  });

  describe("GET /reports/:id/evidence-pack", () => {
    it("needs a signed-in account", async () => {
      app.as(null);
      expect((await get(`/reports/${aliceReport}/evidence-pack`)).status).toBe(401);
    });

    it("gives the owner a zip with the right headers and every file", async () => {
      app.as(alice);
      const res = await get(`/reports/${aliceReport}/evidence-pack`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("application/zip");
      expect(res.headers.get("content-disposition")).toMatch(/^attachment; filename="secscan-evidence-shop\.example\.com-\d{4}-\d{2}-\d{2}\.zip"$/);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const bytes = Buffer.from(await res.arrayBuffer());
      expect(Number(res.headers.get("content-length"))).toBe(bytes.length);
      const files = new Map(readZip(bytes).map((e) => [e.name, e.data]));
      expect([...files.keys()]).toContain("MANIFEST.json");
      expect(JSON.parse(files.get("report.json")!.toString()).summary.grade).toBe("B");
      expect(files.get("summary.md")!.toString()).toContain(`/report/${aliceReport}`);
    });

    it("the manifest hash in the header is the one inside the pack, and the pack's own signature verifies at /evidence/verify", async () => {
      app.as(alice);
      const res = await get(`/reports/${aliceReport}/evidence-pack`);
      const files = new Map(readZip(Buffer.from(await res.arrayBuffer())).map((e) => [e.name, e.data]));
      const sig = JSON.parse(files.get("SIGNATURE.json")!.toString());
      expect(sig.manifestSha256).toBe(res.headers.get("x-manifest-sha256"));
      app.as(null); // anyone can ask
      const ok = await verify({ manifestSha256: sig.manifestSha256, signature: sig.signature });
      expect(await ok.json()).toEqual({ valid: true });
    });

    it("names who it is prepared for when asked, as plain text", async () => {
      app.as(alice);
      const res = await get(`/reports/${aliceReport}/evidence-pack?for=${encodeURIComponent("Acme Ltd\n# Injected")}`);
      const files = new Map(readZip(Buffer.from(await res.arrayBuffer())).map((e) => [e.name, e.data]));
      const summary = files.get("summary.md")!.toString();
      expect(summary).toContain("Prepared for **Acme Ltd # Injected**.");
      expect(summary).not.toMatch(/^# Injected/m);
    });

    it("is not available for someone else's report, a report that does not exist, or a malformed id", async () => {
      app.as(bob);
      for (const id of [aliceReport, MISSING, "not-a-uuid"]) {
        const res = await get(`/reports/${id}/evidence-pack`);
        expect(res.status, id).toBe(404);
        expect(res.headers.get("content-type")).toMatch(/json/);
      }
    });
  });

  describe("POST /evidence/verify", () => {
    it("needs no sign-in, and says a made-up signature is not valid", async () => {
      app.as(null);
      const res = await verify({ manifestSha256: "a".repeat(64), signature: "b".repeat(64) });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ valid: false });
    });

    it("says an edited manifest is not valid", async () => {
      app.as(alice);
      const res = await get(`/reports/${aliceReport}/evidence-pack`);
      const files = new Map(readZip(Buffer.from(await res.arrayBuffer())).map((e) => [e.name, e.data]));
      const sig = JSON.parse(files.get("SIGNATURE.json")!.toString());
      const flipped = (sig.manifestSha256 as string).replace(/^./, (c) => (c === "0" ? "1" : "0"));
      expect(await (await verify({ manifestSha256: flipped, signature: sig.signature })).json()).toEqual({ valid: false });
    });

    it("accepts the hash and signature in upper case", async () => {
      app.as(alice);
      const res = await get(`/reports/${aliceReport}/evidence-pack`);
      const files = new Map(readZip(Buffer.from(await res.arrayBuffer())).map((e) => [e.name, e.data]));
      const sig = JSON.parse(files.get("SIGNATURE.json")!.toString());
      expect(await (await verify({ manifestSha256: sig.manifestSha256.toUpperCase(), signature: sig.signature.toUpperCase() })).json()).toEqual({ valid: true });
    });

    it.each([
      ["no body", undefined],
      ["missing signature", { manifestSha256: "a".repeat(64) }],
      ["numbers", { manifestSha256: 1, signature: 2 }],
      ["too long", { manifestSha256: "a".repeat(65), signature: "b".repeat(64) }],
    ])("refuses a bad request (%s)", async (_label, body) => {
      const res = await verify(body);
      expect(res.status).toBe(400);
    });
  });
});
