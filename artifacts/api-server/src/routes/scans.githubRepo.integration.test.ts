/**
 * The GitHub repository field, from request to stored row, against a REAL Postgres so the new
 * column and its migration are proven, not just typed. Runs only with GHWIRE_TEST_DATABASE_URL
 * (a disposable database; it truncates scans).
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import express from "express";
import request from "supertest";

const URL_ = process.env["GHWIRE_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

// The queue and the target guard are the two things that would reach outside the test.
vi.mock("../lib/queue", () => ({ enqueueScan: vi.fn(async () => undefined) }));
vi.mock("../lib/ssrfGuard", () => ({ checkScanTarget: async () => ({ ok: true }) }));

let app: express.Express;
let dbMod: typeof import("@workspace/db");

suite("scan creation with a GitHub repository (real Postgres)", () => {
  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    const { sql } = await import("drizzle-orm");
    await dbMod.db.execute(sql`TRUNCATE scans CASCADE`);
    const { createScanHandler } = await import("./scans");
    app = express();
    app.use(express.json());
    app.post("/scans", (req, res, next) => {
      Object.assign(req, { user: { id: "gh-user-1", email: "gh@example.test" }, isAuthenticated: () => true });
      createScanHandler(req, res).catch(next);
    });
  }, 60_000);

  afterAll(async () => {
    await dbMod?.pool?.end?.();
  });

  async function rows() {
    const { scansTable } = dbMod;
    return dbMod.db.select({ url: scansTable.targetUrl, repo: scansTable.githubRepoUrl, paidWith: scansTable.paidWith }).from(scansTable);
  }

  it("stores the normalised repository on the scan row", async () => {
    const res = await request(app).post("/scans").send({ targetUrl: "https://example.com", githubRepoUrl: "  acme/shop.git " });
    expect(res.status).toBe(201);
    expect(await rows()).toEqual([{ url: "https://example.com", repo: "https://github.com/acme/shop", paidWith: "free" }]);
  });

  it("stores null when no repository was given", async () => {
    const before = (await rows()).length;
    const res = await request(app).post("/scans").send({ targetUrl: "https://example.org", githubRepoUrl: "   " });
    expect(res.status).toBe(201);
    const all = await rows();
    expect(all).toHaveLength(before + 1);
    expect(all.find((r) => r.url === "https://example.org")?.repo).toBeNull();
  });

  it("refuses a bad repository with a 400 before anything is charged or stored", async () => {
    const before = await rows();
    for (const bad of ["https://gitlab.com/acme/shop", "not a repo", "https://github.com/acme"]) {
      const res = await request(app).post("/scans").send({ targetUrl: "https://example.net", githubRepoUrl: bad });
      expect(res.status, bad).toBe(400);
      expect(res.body.error).toMatch(/GitHub repository/);
    }
    expect(await rows()).toEqual(before);
  });
});
