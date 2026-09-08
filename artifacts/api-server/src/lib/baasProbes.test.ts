import { describe, it, expect, afterEach, vi } from "vitest";
import { runBaasProbes } from "./baasProbes.js";

/**
 * First tests for this module. Nothing reached it before: its only importer is
 * scanner.ts, which has no test file. It can emit a Critical, which makes an
 * untested confirmation step expensive.
 */

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

/** Routes by pathname; anything unlisted 404s. */
function serve(routes: Record<string, { body: string; status?: number }>) {
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const path = new URL(url).pathname;
    const hit = routes[path];
    if (!hit) return new Response("Not Found", { status: 404 });
    return new Response(hit.body, {
      status: hit.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

const PB_PAGE = '<html><body><script>const pb = new PocketBase("https://example.com");pb.collection("users")</script></body></html>';

// What PocketBase actually answers on /api/health.
const PB_HEALTH = JSON.stringify({ code: 200, message: "API is healthy.", data: {} });

describe("runBaasProbes — a real PocketBase with open collections", () => {
  it("reports a collection that returns records without auth", async () => {
    serve({
      "/api/health": { body: PB_HEALTH },
      "/api/collections/users/records": {
        body: JSON.stringify({ page: 1, perPage: 1, totalItems: 412, items: [{ id: "abc", email: "a@b.c" }] }),
      },
    });

    const vulns = await runBaasProbes("https://example.com/", PB_PAGE);
    expect(vulns.length).toBeGreaterThan(0);
    expect(vulns[0]!.severity).toBe("critical");
    expect(vulns[0]!.name).toMatch(/PocketBase/);
    expect(vulns[0]!.name).toMatch(/users/);
  });
});

describe("runBaasProbes — does not invent one", () => {
  it("makes no requests when the page never mentions a BaaS", async () => {
    const calls: string[] = [];
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      calls.push(String(input));
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    expect(await runBaasProbes("https://example.com/", "<html><body>hello</body></html>")).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("stands down when the health endpoint is not PocketBase", async () => {
    // The page mentions PocketBase — a blog post, a job ad, a comparison table
    // — so the origin gets probed. The health check is what must stop it.
    serve({
      "/api/health": { body: JSON.stringify({ service: "orders-api", uptime: 8123 }) },
      "/api/collections/users/records": { body: JSON.stringify({ items: [{ id: 1 }], totalItems: 9 }) },
    });

    const page = "<html><body><article>Why we moved off PocketBase last year</article></body></html>";
    expect(await runBaasProbes("https://example.com/", page)).toEqual([]);
  });

  it("does not report a generic API whose health endpoint says status ok", async () => {
    // A great many services answer /api/health with {"status":"ok"} and are not
    // PocketBase. If a catch-all also answers 200 on the collection paths, that
    // combination must not produce an unauthenticated-access Critical.
    serve({
      "/api/health": { body: JSON.stringify({ status: "ok" }) },
      "/api/collections/users/records": { body: "<html><body>Dashboard</body></html>" },
      "/api/collections/posts/records": { body: "<html><body>Dashboard</body></html>" },
      "/api/collections/orders/records": { body: "<html><body>Dashboard</body></html>" },
    });

    const page = "<html><body><p>We use pocketbase for prototypes.</p></body></html>";
    expect(await runBaasProbes("https://example.com/", page)).toEqual([]);
  });

  it("reports nothing when collections require auth", async () => {
    serve({
      "/api/health": { body: PB_HEALTH },
      "/api/collections/users/records": { body: JSON.stringify({ code: 403, message: "Only admins can access." }), status: 403 },
    });

    expect(await runBaasProbes("https://example.com/", PB_PAGE)).toEqual([]);
  });

  it("survives a URL it cannot parse", async () => {
    serve({});
    expect(await runBaasProbes("not a url", PB_PAGE)).toEqual([]);
  });
});
