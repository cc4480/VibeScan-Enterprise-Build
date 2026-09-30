import { describe, it, expect, afterEach } from "vitest";
import { checkRobotsTxt, checkSecurityTxt } from "./probes.js";

/**
 * Both found by the 2026-09-30 verification of the sweep, both Info-level, both wrong statements:
 *  - npmjs.com answers a scanner HTTP 403 (a Cloudflare challenge) on both security.txt paths while the
 *    file exists; "Missing security.txt" was raised on the refusal.
 *  - wikipedia.org's robots.txt disallows discussion pages about the admin role, which /admin/i matched
 *    inside "Administratoren", "Adminkandidaturen" and "Requests_for_adminship".
 */

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

function serve(routes: Record<string, { status?: number; body?: string }>, fallback = { status: 404, body: "Not Found" }) {
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const hit = routes[url] ?? fallback;
    return new Response(hit.body ?? "", { status: hit.status ?? 200, headers: { "content-type": "text/plain" } });
  }) as typeof fetch;
}

describe("checkSecurityTxt", () => {
  const site = "https://example.com/";
  const wk = "https://example.com/.well-known/security.txt";
  const root = "https://example.com/security.txt";

  it("makes no claim when both paths were refused (HTTP 403)", async () => {
    serve({ [wk]: { status: 403 }, [root]: { status: 403 } });
    expect(await checkSecurityTxt(site)).toEqual([]);
  });

  it("makes no claim when one path was refused, 429-limited, unreachable or erroring", async () => {
    for (const status of [401, 403, 429, 500, 503]) {
      serve({ [wk]: { status }, [root]: { status: 404 } });
      expect(await checkSecurityTxt(site), String(status)).toEqual([]);
    }
    globalThis.fetch = (async () => { throw new Error("connect ETIMEDOUT"); }) as typeof fetch;
    expect(await checkSecurityTxt(site)).toEqual([]);
  });

  it("still reports it missing when both paths answer 404", async () => {
    serve({ [wk]: { status: 404 }, [root]: { status: 404 } });
    const [v] = await checkSecurityTxt(site);
    expect(v!.name).toBe("Missing security.txt (RFC 9116)");
    expect(v!.evidence).toContain("HTTP 404");
  });

  it("still reports a page that is not an RFC 9116 file, and accepts a real one", async () => {
    serve({ [wk]: { status: 200, body: "<html>welcome</html>" }, [root]: { status: 404 } });
    expect(await checkSecurityTxt(site)).toHaveLength(1);
    serve({ [wk]: { status: 200, body: "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n" } });
    expect(await checkSecurityTxt(site)).toEqual([]);
  });
});

describe("checkRobotsTxt sensitive paths", () => {
  const robots = (lines: string[]) => serve({ "https://example.com/robots.txt": { status: 200, body: `User-agent: *\n${lines.map((l) => `Disallow: ${l}`).join("\n")}\n` } });
  const listed = async (lines: string[]) => {
    robots(lines);
    const [v] = await checkRobotsTxt("https://example.com/");
    return v ? (v.evidence ?? "").split("\n").filter((l) => l.startsWith("Disallow:")).map((l) => l.slice(10)) : [];
  };

  it("does not match the word inside other words (wikipedia.org's discussion pages)", async () => {
    expect(
      await listed([
        "/wiki/Wikipedia:Administratoren/Probleme/",
        "/wiki/Wikipedia:Adminkandidaturen/",
        "/wiki/Wikipedia:Requests_for_adminship/",
        "/wiki/Wikipedia%3ARequests_for_adminship/",
        "/wiki/Wikipedia:Administratorer",
        "/wiki/Configuration_management",
        "/wiki/Internalization",
      ]),
    ).toEqual([]);
  });

  it("still finds real admin and configuration paths in every shape seen in the sweep", async () => {
    const seen = ["/admin/", "/index.php/admin/", "*/store/admin", "/*/admin/", "/wp-admin/post.php", "/fizzy/admin", "/web.config", "/config/newrelic/prod"];
    expect(await listed(seen)).toEqual(seen);
    const more = ["/administrator/", "/backup/", "/private/", "/staging/app", "/.env", "/dump.sql"];
    expect(await listed(more)).toEqual(more);
  });

  it("finds each remaining sensitive keyword as a path segment", async () => {
    const kw = ["/secret/keys", "/internal/tools", "/database/export", "/debug/", "/credentials/list", "/backups/2026", "/db/", "/logs/"];
    expect(await listed(kw)).toEqual(kw);
  });
});
