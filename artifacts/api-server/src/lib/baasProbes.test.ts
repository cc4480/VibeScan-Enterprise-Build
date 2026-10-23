import { describe, it, expect } from "vitest";
import { runBaasProbes } from "./baasProbes.js";
import { useRouteSite } from "./routeSite.testkit";

// The site is a real web server on loopback (lib/routeSite.testkit.ts); what it serves at each path is set per test.
const site = await useRouteSite();

/**
 * First tests for this module. Nothing reached it before: its only importer is
 * scanner.ts, which has no test file. It can emit a Critical, which makes an
 * untested confirmation step expensive.
 */

/** Routes by pathname; anything unlisted 404s. */
function serve(routes: Record<string, { body: string; status?: number }>) {
  site.routes(routes);
}

const PB_PAGE = `<html><body><script>const pb = new PocketBase("${site.origin}");pb.collection("users")</script></body></html>`;

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

    const vulns = await runBaasProbes(`${site.origin}/`, PB_PAGE);
    expect(vulns.length).toBeGreaterThan(0);
    expect(vulns[0]!.severity).toBe("critical");
    expect(vulns[0]!.name).toMatch(/PocketBase/);
    expect(vulns[0]!.name).toMatch(/users/);
  });
});

describe("runBaasProbes — does not invent one", () => {
  it("makes no requests when the page never mentions a BaaS", async () => {
    expect(await runBaasProbes(`${site.origin}/`, "<html><body>hello</body></html>")).toEqual([]);
    expect(site.seen).toEqual([]);
  });

  it("stands down when the health endpoint is not PocketBase", async () => {
    // The page mentions PocketBase — a blog post, a job ad, a comparison table
    // — so the origin gets probed. The health check is what must stop it.
    serve({
      "/api/health": { body: JSON.stringify({ service: "orders-api", uptime: 8123 }) },
      "/api/collections/users/records": { body: JSON.stringify({ items: [{ id: 1 }], totalItems: 9 }) },
    });

    const page = "<html><body><article>Why we moved off PocketBase last year</article></body></html>";
    expect(await runBaasProbes(`${site.origin}/`, page)).toEqual([]);
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
    expect(await runBaasProbes(`${site.origin}/`, page)).toEqual([]);
  });

  it("reports nothing when collections require auth", async () => {
    serve({
      "/api/health": { body: PB_HEALTH },
      "/api/collections/users/records": { body: JSON.stringify({ code: 403, message: "Only admins can access." }), status: 403 },
    });

    expect(await runBaasProbes(`${site.origin}/`, PB_PAGE)).toEqual([]);
  });

  it("survives a URL it cannot parse", async () => {
    serve({});
    expect(await runBaasProbes("not a url", PB_PAGE)).toEqual([]);
  });
});

describe("runBaasProbes — public-by-design and empty lists", () => {
  const list = (items: unknown[], total = items.length) =>
    JSON.stringify({ page: 1, perPage: 1, totalItems: total, items });
  const HIGH_OR_WORSE = ["critical", "high"];

  it("PocketBase 200 with empty items is not HIGH (list rule filtering to nothing) — clean twin", async () => {
    serve({ "/api/health": { body: PB_HEALTH }, "/api/collections/users/records": { body: list([]) } });
    const vulns = await runBaasProbes(`${site.origin}/`, PB_PAGE);
    expect(vulns.filter((v) => HIGH_OR_WORSE.includes(v.severity))).toEqual([]);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("info");
  });

  it("PocketBase public catalogue records are INFO", async () => {
    serve({
      "/api/health": { body: PB_HEALTH },
      "/api/collections/products/records": { body: list([{ id: "p1", name: "Mug", price: 3 }]) },
    });
    const vulns = await runBaasProbes(`${site.origin}/`, PB_PAGE);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("info");
  });

  it("PocketBase records from a public-sounding collection with an email column stay CRITICAL", async () => {
    serve({
      "/api/health": { body: PB_HEALTH },
      "/api/collections/posts/records": { body: list([{ id: "p1", title: "x", author_email: "a@b.co" }]) },
    });
    const vulns = await runBaasProbes(`${site.origin}/`, PB_PAGE);
    expect(vulns[0]!.severity).toBe("critical");
  });

  const AW_PAGE =
    `<script>import { Client } from "appwrite"; new Client().setEndpoint("${site.origin}/v1").setProject("abcdef0123456789abcd")</script>`;
  const awServe = (docs: unknown[], collection: string) =>
    serve({
      "/v1/health": { body: "{}" },
      [`/v1/databases/default/collections/${collection}/documents`]: { body: JSON.stringify({ total: docs.length, documents: docs }) },
    });

  it("Appwrite empty documents is not HIGH — clean twin", async () => {
    awServe([], "users");
    const vulns = await runBaasProbes(`${site.origin}/`, AW_PAGE);
    expect(vulns.filter((v) => HIGH_OR_WORSE.includes(v.severity))).toEqual([]);
  });

  it("Appwrite documents from users are still CRITICAL; from posts are INFO", async () => {
    awServe([{ $id: "1", email: "a@b.co" }], "users");
    expect((await runBaasProbes(`${site.origin}/`, AW_PAGE))[0]!.severity).toBe("critical");
    awServe([{ $id: "1", title: "Hello" }], "posts");
    expect((await runBaasProbes(`${site.origin}/`, AW_PAGE))[0]!.severity).toBe("info");
  });
});
