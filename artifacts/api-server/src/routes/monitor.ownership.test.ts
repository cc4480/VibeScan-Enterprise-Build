import { describe, it, expect, vi, beforeEach } from "vitest";
import { wheres, queuedResults, eqsIn, makeRes, makeReq, idRoutes, mockFactory1, mockFactory2, mockFactory3, mockFactory4, mockFactory5, mockFactory6, mockFactory7, mockFactory8, mockFactory9, resetState } from "./monitor.testkit";

// Shared mock factories live in monitor.testkit.ts; vi.mock has to be written in the test file itself.
vi.mock("@workspace/db", () => mockFactory1());
vi.mock("drizzle-orm", () => mockFactory2());
vi.mock("../lib/queue", () => mockFactory3());
vi.mock("../lib/logger", () => mockFactory4());
vi.mock("../lib/ssrfGuard", () => mockFactory5());
vi.mock("../lib/rateLimit", () => mockFactory6());
vi.mock("../lib/billing", () => mockFactory7());
vi.mock("../lib/credits", () => mockFactory8());
vi.mock("../lib/freeTrial", () => mockFactory9());

beforeEach(resetState);

describe("/monitor/subscriptions/:id — ownership", () => {
  it("finds the :id endpoints this file is meant to guard", async () => {
    // If this ever reads 0, every test below would pass while asserting
    // nothing — the failure mode that makes structural tests worthless.
    const routes = await idRoutes();
    expect(routes.length).toBeGreaterThanOrEqual(6);
  });

  it("scopes every subscription lookup by the caller's own user id", async () => {
    for (const { label, handle } of await idRoutes()) {
      wheres.length = 0;
      await handle(makeReq(), makeRes());

      // The first lookup a handler makes is the subscription itself. It must
      // constrain BOTH the id from the URL and the caller — an id-only lookup
      // is the IDOR.
      const first = eqsIn(wheres[0]);
      const byId = first.some((e) => String(e.col).endsWith(".id"));
      const byOwner = first.some(
        (e) => String(e.col).endsWith(".userId") && e.val === "user-1",
      );

      expect(byId, `${label} must constrain the subscription id`).toBe(true);
      expect(byOwner, `${label} must constrain userId to the caller`).toBe(true);
    }
  });

  it("answers 404, not 403, when the subscription is not the caller's", async () => {
    // The mock resolves every query to [], which is what a scoped lookup
    // returns for someone else's subscription. 404 rather than 403 matters:
    // 403 would confirm the id exists.
    for (const { label, handle } of await idRoutes()) {
      const res = makeRes();
      await handle(makeReq(), res);
      expect(res.statusCode, label).toBe(404);
    }
  });

  it("refuses an unauthenticated caller before touching the database", async () => {
    for (const { label, handle } of await idRoutes()) {
      wheres.length = 0;
      const res = makeRes();
      await handle(makeReq({ isAuthenticated: () => false, user: undefined }), res);

      expect(res.statusCode, label).toBe(401);
      // Auth first, so an anonymous caller cannot spend queries — or, on the
      // rescan endpoint, a real user's scan budget.
      expect(wheres, `${label} queried the db while unauthenticated`).toHaveLength(0);
    }
  });
});

describe("GET /monitor/subscriptions/:id/history — trend data", () => {
  it("maps vulnCount from the report's real totalVulnerabilities field", async () => {
    // The route used to read `data.summary.vulnCount`, a key that has never
    // existed on a stored report (worker.ts writes `totalVulnerabilities`) —
    // every history entry, for every subscription, returned vulnCount: null.
    queuedResults.push([{ id: "sub-1" }]); // ownership lookup
    queuedResults.push([
      {
        id: "report-1",
        scanId: "scan-1",
        scannedAt: new Date("2026-09-01T00:00:00.000Z"),
        tier: "deep",
        data: { summary: { grade: "B", riskScore: 22, totalVulnerabilities: 7 } },
      },
    ]); // the reports query

    const routes = await idRoutes();
    const history = routes.find((r) => r.label.includes("/history"));
    expect(history, "no GET .../history route found").toBeDefined();

    const res = makeRes();
    await history!.handle(makeReq(), res);

    const body = res.body as Array<{ vulnCount: number | null; grade: string | null }>;
    expect(body[0]?.grade).toBe("B");
    expect(body[0]?.vulnCount).toBe(7);
  });

  it("counts from the list without the scan's notes when the report has one", async () => {
    queuedResults.push([{ id: "sub-1" }]);
    queuedResults.push([
      {
        id: "report-1", scanId: "scan-1", scannedAt: new Date("2026-09-01T00:00:00.000Z"), tier: "deep",
        // Saved before notes were left out of the total: it says 4, the list holds 3 findings and a note.
        data: {
          summary: { grade: "B", riskScore: 22, totalVulnerabilities: 4 },
          vulnerabilities: [{ category: "a" }, { category: "b" }, { category: "c" }, { category: "Scan Coverage" }],
        },
      },
    ]);
    const routes = await idRoutes();
    const history = routes.find((r) => r.label.includes("/history"));
    const res = makeRes();
    await history!.handle(makeReq(), res);
    expect((res.body as Array<{ vulnCount: number | null }>)[0]?.vulnCount).toBe(3);
  });
});
