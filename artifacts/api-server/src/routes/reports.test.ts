import { describe, it, expect, vi } from "vitest";

/**
 * GET /reports/:id validates the stored report against a strict schema that does
 * not list `tests` or `compliance`. Those must still reach the owner: without the
 * test ledger the report says "not recorded" and the OWASP card says "no record"
 * for every category, on a scan that recorded all of it.
 */

const stored = {
  vulnerabilities: [],
  summary: { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, riskScore: 0, grade: "A", executiveSummary: "ok" },
  technologies: [],
  targetUrl: "https://example.com",
  tests: [{ group: "passive", name: "JWT analysis", status: "ran", findings: 0, durationMs: 3 }],
  compliance: { frameworks: [], disclaimer: "Not a compliance verdict." },
};

// The comparison with the previous scan is tested in scanDiff*.test.ts; here it is a stand-in.
const loader: { result: unknown; fail: boolean } = { result: null, fail: false };
vi.mock("../lib/scanDiffLoader", () => ({
  changesForReport: async () => {
    if (loader.fail) throw new Error("db down");
    return loader.result;
  },
}));

vi.mock("@workspace/db", () => {
  const chain = {
    select: () => chain,
    from: () => chain,
    where: () =>
      Promise.resolve([
        {
          id: "r1",
          scanId: "s1",
          userId: "u1",
          targetUrl: "https://example.com",
          tier: "deep",
          scannedAt: new Date(),
          duration: 10,
          createdAt: new Date(),
          data: stored,
        },
      ]),
  };
  return { db: chain, reportsTable: { id: "id", userId: "user_id" } };
});

async function get(): Promise<any> {
  const mod = await import("./reports.js");
  const router = mod.default as unknown as {
    stack: { route?: { path: string; stack: { handle: (...a: any[]) => Promise<void> }[] } }[];
  };
  const layer = router.stack.find((l) => l.route?.path === "/reports/:id")!;
  let body: any;
  const res: any = { statusCode: 200, status(c: number) { this.statusCode = c; return this; }, json(b: any) { body = b; return this; } };
  await layer.route!.stack[0]!.handle(
    { isAuthenticated: () => true, user: { id: "u1" }, params: { id: "11111111-1111-4111-8111-111111111111" }, log: { error() {}, warn() {} } },
    res,
  );
  return body;
}

describe("GET /reports/:id", () => {
  it("attaches what changed since the last scan, when there is a previous one", async () => {
    loader.result = { since: { scanId: "s0", scannedAt: "2026-09-20T10:00:00.000Z" }, unchanged: 2, added: [], firstSeen: [], fixed: [{ name: "x", severity: "high", category: "c" }], notRechecked: [], newlyRun: [], noLongerRun: [], differentAccess: false };
    const body = await get();
    expect(body.data.changes.fixed).toHaveLength(1);
    expect(body.data.tests).toEqual(stored.tests);
    loader.result = null;
  });

  it("leaves changes out for a first scan", async () => {
    loader.result = null;
    expect((await get()).data.changes).toBeUndefined();
  });

  it("still returns the report when the comparison fails: it must never cost someone their report", async () => {
    loader.fail = true;
    const body = await get();
    expect(body.data.tests).toEqual(stored.tests);
    expect(body.data.changes).toBeUndefined();
    loader.fail = false;
  });

  it("returns the stored test ledger and compliance mapping to the owner", async () => {
    const body = await get();
    expect(body.data.tests).toEqual(stored.tests);
    expect(body.data.compliance).toEqual(stored.compliance);
    // and still validates the fields it does list
    expect(body.data.summary.grade).toBe("A");
  });
});
