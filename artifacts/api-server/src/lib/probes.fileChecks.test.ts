import { describe, it, expect } from "vitest";
import { checkRobotsTxt, checkSecurityTxt } from "./probes.js";
import { useRouteSite } from "./routeSite.testkit";

// The site is a real web server on loopback (lib/routeSite.testkit.ts); what it serves at each path is set per test.
const site = await useRouteSite();

/**
 * Both found by the 2026-09-30 verification of the sweep, both Info-level, both wrong statements:
 *  - npmjs.com answers a scanner HTTP 403 (a Cloudflare challenge) on both security.txt paths while the
 *    file exists; "Missing security.txt" was raised on the refusal.
 *  - wikipedia.org's robots.txt disallows discussion pages about the admin role, which /admin/i matched
 *    inside "Administratoren", "Adminkandidaturen" and "Requests_for_adminship".
 */

/** Serve these paths as text; any other path answers `fallback`. */
function serve(routes: Record<string, { status?: number; body?: string }>, fallback = { status: 404, body: "Not Found" }) {
  const table: Record<string, { status: number; body: string; ct: string }> = {};
  for (const [path, hit] of Object.entries(routes)) table[path] = { status: hit.status ?? 200, body: hit.body ?? "", ct: "text/plain" };
  site.routes(table);
  site.otherwise(() => ({ status: fallback.status, body: fallback.body, ct: "text/plain" }));
}

describe("checkSecurityTxt", () => {
  const home = `${site.origin}/`;
  const wk = "/.well-known/security.txt";
  const root = "/security.txt";

  it("makes no claim when both paths were refused (HTTP 403)", async () => {
    serve({ [wk]: { status: 403 }, [root]: { status: 403 } });
    expect(await checkSecurityTxt(home)).toEqual([]);
  });

  it("makes no claim when one path was refused, 429-limited, unreachable or erroring", async () => {
    for (const status of [401, 403, 429, 500, 503]) {
      serve({ [wk]: { status }, [root]: { status: 404 } });
      expect(await checkSecurityTxt(home), String(status)).toEqual([]);
    }
    site.routes({});
    site.otherwise(() => ({ drop: true })); // the site cuts every connection
    expect(await checkSecurityTxt(home)).toEqual([]);
  });

  it("still reports it missing when both paths answer 404", async () => {
    serve({ [wk]: { status: 404 }, [root]: { status: 404 } });
    const [v] = await checkSecurityTxt(home);
    expect(v!.name).toBe("Missing security.txt (RFC 9116)");
    expect(v!.evidence).toContain("HTTP 404");
  });

  it("still reports a page that is not an RFC 9116 file, and accepts a real one", async () => {
    serve({ [wk]: { status: 200, body: "<html>welcome</html>" }, [root]: { status: 404 } });
    expect(await checkSecurityTxt(home)).toHaveLength(1);
    serve({ [wk]: { status: 200, body: "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n" } });
    expect(await checkSecurityTxt(home)).toEqual([]);
  });
});

describe("checkRobotsTxt sensitive paths", () => {
  const robots = (lines: string[]) => serve({ "/robots.txt": { status: 200, body: `User-agent: *\n${lines.map((l) => `Disallow: ${l}`).join("\n")}\n` } });
  const listed = async (lines: string[]) => {
    robots(lines);
    const [v] = await checkRobotsTxt(`${site.origin}/`);
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
