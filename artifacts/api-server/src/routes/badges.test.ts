import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The public badge endpoint. It is an image other sites embed, so the headers matter as
 * much as the body: the rest of /api sends Cross-Origin-Resource-Policy: same-origin and
 * no-store, either of which would silently break a badge pasted into a README.
 */

const queue: unknown[][] = [];
const updates: unknown[] = [];
const inserts: unknown[] = [];
const dbState = { fail: false };

vi.mock("@workspace/db", () => {
  const chain: any = {
    select: () => chain,
    from: () => chain,
    where: () => {
      const result = dbState.fail ? Promise.reject(new Error("db down")) : Promise.resolve(queue.shift() ?? []);
      // ensureReportBadge ends with .limit(1); the badge route awaits where() directly.
      return Object.assign(result, { limit: () => result });
    },
    update: () => ({ set: (v: unknown) => { updates.push(v); return { where: () => Promise.resolve() }; } }),
    insert: () => ({ values: (v: unknown) => { inserts.push(v); return Promise.resolve(); } }),
  };
  return {
    db: chain,
    reportsTable: { id: "id", userId: "user_id", data: "data", scannedAt: "scanned_at" },
    reportBadgesTable: { token: "token", reportId: "report_id", revokedAt: "revoked_at" },
  };
});
vi.mock("drizzle-orm", () => ({ eq: () => ({}), and: () => ({}), isNull: () => ({}) }));

beforeEach(() => {
  queue.length = 0;
  updates.length = 0;
  inserts.length = 0;
  dbState.fail = false;
});

type Handler = (req: any, res: any) => Promise<void>;

async function handler(method: "get" | "post" | "delete", path: string): Promise<Handler> {
  const mod = await import("./badges.js");
  const router = mod.default as unknown as {
    stack: { route?: { path: string; methods: Record<string, boolean>; stack: { handle: Handler }[] } }[];
  };
  const layer = router.stack.find((l) => l.route?.path === path && l.route.methods[method])!;
  return layer.route!.stack[0]!.handle;
}

function fakeRes() {
  const headers: Record<string, string> = {};
  const res: any = {
    statusCode: 200,
    headers,
    body: undefined as unknown,
    contentType: "",
    status(c: number) { res.statusCode = c; return res; },
    type(t: string) { res.contentType = t; return res; },
    set(h: Record<string, string>) { Object.assign(headers, h); return res; },
    removeHeader(n: string) { delete headers[n]; },
    json(b: unknown) { res.body = b; return res; },
    send(b?: unknown) { res.body = b; return res; },
  };
  return res;
}

const token = "abcdefghijklmnopqrstuvwx";
const get = async (file: string) => {
  const res = fakeRes();
  await (await handler("get", "/badge/:file"))({ params: { file }, log: { error() {} } }, res);
  return res;
};

describe("GET /badge/:token.svg", () => {
  it("serves the grade and date as an image other sites can embed", async () => {
    queue.push([{ reportId: "r1" }], [{ data: { summary: { grade: "B" } }, scannedAt: new Date() }]);

    const res = await get(`${token}.svg`);

    expect(res.statusCode).toBe(200);
    expect(res.contentType).toBe("image/svg+xml");
    expect(res.body).toContain("grade B");
    // Without these two a badge would not load on any other site, or would hit the database per view.
    expect(res.headers["Cross-Origin-Resource-Policy"]).toBe("cross-origin");
    expect(res.headers["Cache-Control"]).toBe("public, max-age=3600");
    expect(res.headers["Content-Security-Policy"]).toContain("default-src 'none'");
  });

  it("never puts the address, a finding or a report id in the image", async () => {
    queue.push(
      [{ reportId: "report-id-123" }],
      [{ data: { targetUrl: "https://secret.example.com", vulnerabilities: [{ name: "SQL Injection" }], summary: { grade: "F" } }, scannedAt: new Date() }],
    );

    const body = (await get(`${token}.svg`)).body as string;

    expect(body).not.toContain("secret.example.com");
    expect(body).not.toContain("SQL Injection");
    expect(body).not.toContain("report-id-123");
  });

  it("answers an unknown token, a revoked one and a malformed one identically", async () => {
    // No oracle for which tokens exist. The revoked and unknown cases both miss the lookup.
    queue.push([]); // unknown or revoked: no row
    const unknown = await get(`${token}.svg`);
    const malformed = await get("not-a-token.svg");
    const noExtension = await get(token);

    for (const r of [unknown, malformed, noExtension]) {
      expect(r.statusCode).toBe(404);
      expect(r.body).toContain("badge not found");
      expect(r.contentType).toBe("image/svg+xml");
      expect(r.headers["Cross-Origin-Resource-Policy"]).toBe("cross-origin");
    }
    expect(unknown.body).toBe(malformed.body);
  });

  it("does not touch the database for a malformed token", async () => {
    queue.push([{ reportId: "r1" }]);
    await get("../../etc/passwd.svg");
    expect(queue).toHaveLength(1); // the queued row was never consumed
  });

  it("reads 'not graded' for a scan a challenge page answered", async () => {
    queue.push([{ reportId: "r1" }], [{ data: { summary: { grade: "N/A" } }, scannedAt: new Date() }]);
    expect((await get(`${token}.svg`)).body).toContain("not graded");
  });

  it("answers a database failure with a visible placeholder that is not cached", async () => {
    dbState.fail = true;

    const res = await get(`${token}.svg`);

    expect(res.statusCode).toBe(500);
    expect(res.body).toContain("badge not found");
    // A database blip must not pin a broken badge in every browser for an hour.
    expect(res.headers["Cache-Control"]).toBe("no-store");
  });
});

describe("POST and DELETE /reports/:id/badge", () => {
  const owner = { isAuthenticated: () => true, user: { id: "u1" }, params: { id: "r1" }, log: { error() {} } };

  it("refuses an anonymous caller", async () => {
    const res = fakeRes();
    await (await handler("post", "/reports/:id/badge"))({ ...owner, isAuthenticated: () => false }, res);
    expect(res.statusCode).toBe(401);
    expect(inserts).toHaveLength(0);
  });

  it("refuses someone else's report", async () => {
    queue.push([{ id: "r1", userId: "someone-else" }]);
    const res = fakeRes();
    await (await handler("post", "/reports/:id/badge"))(owner, res);
    expect(res.statusCode).toBe(403);
    expect(inserts).toHaveLength(0);
  });

  it("mints a badge for the owner and returns copy-paste snippets that do not link to a share", async () => {
    queue.push([{ id: "r1", userId: "u1" }], []); // owned report, then no existing badge
    const res = fakeRes();
    await (await handler("post", "/reports/:id/badge"))(owner, res);
    expect(res.statusCode).toBe(201);
    expect(inserts).toHaveLength(1);
    const body = res.body as { token: string; markdown: string; imageUrl: string };
    expect(body.imageUrl).toContain(`/api/badge/${body.token}.svg`);
    expect(body.markdown).not.toContain("/share/");
  });

  it("hands back the same badge when one already exists, instead of minting a second", async () => {
    queue.push([{ id: "r1", userId: "u1" }], [{ token: "existing-token-aaaaaaaaaa" }]);
    const res = fakeRes();
    await (await handler("post", "/reports/:id/badge"))(owner, res);
    expect((res.body as { token: string }).token).toBe("existing-token-aaaaaaaaaa");
    expect(inserts).toHaveLength(0);
  });

  it("revokes the owner's badge", async () => {
    queue.push([{ id: "r1", userId: "u1" }]);
    const res = fakeRes();
    await (await handler("delete", "/reports/:id/badge"))(owner, res);
    expect(res.statusCode).toBe(204);
    expect(updates).toHaveLength(1);
    expect((updates[0] as { revokedAt: unknown }).revokedAt).toBeInstanceOf(Date);
  });

  it("will not revoke someone else's badge", async () => {
    queue.push([{ id: "r1", userId: "someone-else" }]);
    const res = fakeRes();
    await (await handler("delete", "/reports/:id/badge"))(owner, res);
    expect(res.statusCode).toBe(403);
    expect(updates).toHaveLength(0);
  });
});
