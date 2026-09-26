import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";

const USER = { id: "u1", email: "dev@example.com", firstName: "Dev", lastName: null, profileImageUrl: null };
const SCAN_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ID = "22222222-2222-4222-8222-222222222222";

const state = {
  scans: {} as Record<string, { id: string; targetUrl: string; status: string; error: string | null; createdAt: Date; completedAt: Date | null }>,
  reports: {} as Record<string, { id: string; targetUrl: string; scannedAt: Date; data: unknown }>,
  launch: { status: 201, body: { scanId: SCAN_ID, paidWith: "free" } as Record<string, unknown> },
  scopeAsked: [] as string[],
};

vi.mock("../lib/apiTokens", () => ({
  // Only an "api"-scope token opens the API; anything else, including a valid "mcp" token, is refused.
  authenticateApiToken: async (header: string | undefined, scope = "mcp") => {
    state.scopeAsked.push(scope);
    if (header === "Bearer ssk_api_token" && scope === "api") return USER;
    return null;
  },
}));

vi.mock("./appRouteRunner", () => ({
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  launchScan: async () => state.launch,
  // Scoped to the caller, like the real one: another user's scan is simply not found.
  ownScan: async (userId: string, id: string) => (userId === "u1" ? (state.scans[id] ?? null) : null),
  reportForScan: async (_userId: string, id: string) => state.reports[id] ?? null,
}));

vi.mock("@workspace/db", () => ({
  scansTable: {},
  db: { select: () => ({ from: () => ({ where: () => ({ orderBy: () => ({ limit: async () => [{ id: SCAN_ID, url: "https://a.example", status: "complete" }] }) }) }) }) },
}));
vi.mock("drizzle-orm", () => ({ desc: () => ({}), eq: () => ({}) }));

import v1 from "./v1";
import { API_V1_SPEC } from "../lib/apiV1Spec";

let base = "";
let server: ReturnType<ReturnType<typeof express>["listen"]>;

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api", v1);
  await new Promise<void>((r) => { server = app.listen(0, "127.0.0.1", () => r()); });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
});
afterAll(() => { server.close(); });

beforeEach(() => {
  state.scopeAsked.length = 0;
  state.launch = { status: 201, body: { scanId: SCAN_ID, paidWith: "free" } };
  state.scans = {
    [SCAN_ID]: { id: SCAN_ID, targetUrl: "https://a.example", status: "complete", error: null, createdAt: new Date(), completedAt: new Date() },
  };
  state.reports = {
    [SCAN_ID]: {
      id: "r1", targetUrl: "https://a.example", scannedAt: new Date(),
      data: {
        summary: { grade: "B", riskScore: 21 },
        vulnerabilities: [{ severity: "high" }, { severity: "low" }, { severity: "low" }],
        tests: [{ group: "g", name: "a", status: "ran", findings: 1, durationMs: 1 }, { group: "g", name: "b", status: "skipped", findings: 0, durationMs: 0 }],
      },
    },
  };
});

const auth = { authorization: "Bearer ssk_api_token" };
// The API answers JSON; the tests read it loosely.
type Res = Omit<Response, "json"> & { json(): Promise<any> };
const get = (path: string, headers: Record<string, string> = auth) => fetch(base + path, { headers }) as Promise<Res>;
const post = (path: string, body: unknown, headers: Record<string, string> = auth) =>
  fetch(base + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) }) as Promise<Res>;

describe("authentication", () => {
  it("refuses a request with no token, in the API's own error shape", async () => {
    const res = await get("/v1/me", {});
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("Bearer");
    expect((await res.json()).error.code).toBe("unauthorized");
  });

  it("asks for the api scope, so a valid MCP token is refused", async () => {
    const res = await get("/v1/me", { authorization: "Bearer ssk_mcp_token" });
    expect(res.status).toBe(401);
    expect(state.scopeAsked).toEqual(["api"]);
  });

  it("accepts an api token", async () => {
    const res = await get("/v1/me");
    expect(res.status).toBe(200);
    expect((await res.json()).email).toBe("dev@example.com");
  });

  it("serves the OpenAPI document without a token", async () => {
    const res = await get("/v1/openapi.json", {});
    expect(res.status).toBe(200);
    expect((await res.json()).openapi).toBe("3.1.0");
  });
});

describe("POST /v1/scans", () => {
  it("queues a scan and returns its id", async () => {
    const res = await post("/v1/scans", { url: "https://a.example" });
    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body).toMatchObject({ id: SCAN_ID, status: "queued", paidWith: "free" });
  });

  it("rejects a body without a url", async () => {
    for (const bad of [{}, { url: "" }, { url: 5 }]) {
      const res = await post("/v1/scans", bad);
      expect(res.status).toBe(400);
      expect((await res.json()).error.code).toBe("invalid_request");
    }
  });

  it("passes the website's refusal through with a stable code", async () => {
    state.launch = { status: 429, body: { error: "Rate limit reached" } };
    const res = await post("/v1/scans", { url: "https://a.example" });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: { code: "rate_limited", message: "Rate limit reached" } });

    state.launch = { status: 402, body: { error: "No scans left" } };
    expect((await (await post("/v1/scans", { url: "https://a.example" })).json()).error.code).toBe("payment_required");
  });
});

describe("GET /v1/scans/:id", () => {
  it("returns a short summary of a finished scan", async () => {
    const body = await (await get(`/v1/scans/${SCAN_ID}`)).json();
    expect(body).toMatchObject({
      id: SCAN_ID, status: "complete", grade: "B", riskScore: 21,
      findings: { high: 1, low: 2, total: 3 },
      coverage: { ran: 1, skipped: 1, failed: 0, total: 2 },
    });
    expect(body.links.report).toContain(`/scans/${SCAN_ID}/report`);
  });

  it("returns only the status while a scan is running", async () => {
    state.scans[SCAN_ID]!.status = "scanning";
    const body = await (await get(`/v1/scans/${SCAN_ID}`)).json();
    expect(body.status).toBe("scanning");
    expect(body.grade).toBeUndefined();
  });

  it("answers 404, never 403, for someone else's scan and for a malformed id", async () => {
    expect((await get(`/v1/scans/${OTHER_ID}`)).status).toBe(404);
    expect((await get("/v1/scans/not-a-uuid")).status).toBe(404);
  });

  it("does not wait when the scan is already finished, even if asked to", async () => {
    const started = Date.now();
    const res = await get(`/v1/scans/${SCAN_ID}?wait=60`);
    expect(res.status).toBe(200);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

describe("GET /v1/scans/:id/report", () => {
  it("returns the full report for a finished scan", async () => {
    const body = await (await get(`/v1/scans/${SCAN_ID}/report`)).json();
    expect(body.report.summary.grade).toBe("B");
    expect(body.url).toBe("https://a.example");
  });

  it("says not_ready (409) for an unfinished scan", async () => {
    state.scans[SCAN_ID]!.status = "queued";
    const res = await get(`/v1/scans/${SCAN_ID}/report`);
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe("not_ready");
  });

  it("404s another user's scan", async () => {
    expect((await get(`/v1/scans/${OTHER_ID}/report`)).status).toBe(404);
  });
});

describe("GET /v1/scans/:id/sarif", () => {
  it("returns the findings as a SARIF log", async () => {
    state.reports[SCAN_ID]!.data = {
      vulnerabilities: [{ name: "Open Redirect Vulnerability", severity: "medium", description: "d", evidence: "GET https://a.example/r", solution: "s" }],
    };
    const res = await get(`/v1/scans/${SCAN_ID}/sarif`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("sarif+json");
    const log = await res.json();
    expect(log.version).toBe("2.1.0");
    expect(log.runs[0].results).toHaveLength(1);
  });

  it("says not_ready for an unfinished scan and 404s someone else's", async () => {
    state.scans[SCAN_ID]!.status = "scanning";
    expect((await get(`/v1/scans/${SCAN_ID}/sarif`)).status).toBe(409);
    expect((await get(`/v1/scans/${OTHER_ID}/sarif`)).status).toBe(404);
  });
});

describe("the rest of /v1", () => {
  it("lists recent scans", async () => {
    const body = await (await get("/v1/scans")).json();
    expect(body.scans).toHaveLength(1);
  });

  it("answers an unknown path in the API's own JSON error shape", async () => {
    const res = await get("/v1/nope");
    expect(res.status).toBe(404);
    expect((await res.json()).error.code).toBe("not_found");
  });
});

describe("the spec describes exactly the routes that exist", () => {
  it("has a spec entry for every route and a route for every spec entry", () => {
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
