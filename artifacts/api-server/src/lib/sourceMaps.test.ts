import { describe, it, expect } from "vitest";
import dns from "node:dns/promises";
import { checkSourceMaps } from "./sourceMaps.js";
import { useRouteSite } from "./routeSite.testkit";

// The site is a real web server on loopback (lib/routeSite.testkit.ts); what it serves at each path is set per test. The
// two tests about a script or map on another host use cdn.lvh.me, a real public name that resolves to 127.0.0.1, and are
// skipped if it does not resolve (offline).
const site = await useRouteSite();
const OTHER_HOST_RESOLVES = await dns.lookup("cdn.lvh.me", { all: true }).then((a) => a.some((x) => x.address === "127.0.0.1"), () => false);

/**
 * Until now nothing exercised this module: its only importer is scanner.ts,
 * which has no test file of its own, so no test reached it directly or
 * indirectly. It emits a High CWE-540 finding, which makes it exactly the kind
 * of module a false positive can sit in indefinitely.
 *
 * The cases below are the ones that would produce a wrong High: a catch-all
 * that answers 200 to everything, a JSON error page, and a CDN-hosted library
 * that publishes its maps deliberately.
 */

/** Serves specific paths; anything else 404s, like a normal origin. */
function serve(routes: Record<string, { body: string; status?: number; ct?: string }>) {
  site.routes(routes);
}

const page = (src: string) => `<html><body><script src="${src}"></script></body></html>`;

const realMap = JSON.stringify({
  version: 3,
  sources: ["src/app.ts", "src/secret-logic.ts"],
  sourcesContent: ["export const a = 1;", "const KEY = 'hunter2';"],
  mappings: "AAAA",
});

const mapWithoutContent = JSON.stringify({
  version: 3,
  sources: ["src/app.ts", "src/util.ts"],
  mappings: "AAAA",
});

describe("checkSourceMaps — reports a genuinely exposed map", () => {
  it("reports a map served directly alongside the bundle", async () => {
    serve({
      "/assets/app.js.map": { body: realMap },
    });

    const vulns = await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("high");
    expect(vulns[0]!.cweId).toBe("CWE-540");
    expect(vulns[0]!.evidence).toMatch(/Source files mapped: 2/);
    expect(vulns[0]!.evidence).toMatch(/sourcesContent/);
  });

  it("reads a map larger than the default 5 MiB body limit whole: the app's own code sits after the libraries, past the old cut", async () => {
    const big = JSON.stringify({
      version: 3,
      sources: ["node_modules/some-lib/index.js", "src/app.ts", "src/secret-logic.ts"],
      sourcesContent: ["x".repeat(6 * 1024 * 1024), "export const a = 1;", "const KEY = 'hunter2';"],
      mappings: "AAAA",
    });
    expect(big.length).toBeGreaterThan(5 * 1024 * 1024);
    serve({ "/assets/app.js.map": { body: big } });
    const vulns = await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("high");
    expect(vulns[0]!.evidence).toMatch(/Source files mapped: 3/);
  });

  it("follows a sourceMappingURL comment in the bundle trailer", async () => {
    serve({
      "/assets/app.js": { body: "//# sourceMappingURL=app.abc123.map", ct: "application/javascript" },
      "/assets/app.abc123.map": { body: realMap },
    });

    const vulns = await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.evidence).toMatch(/app\.abc123\.map/);
  });

  it("reports only once when several bundles expose maps", async () => {
    serve({
      "/a.js.map": { body: realMap },
      "/b.js.map": { body: realMap },
    });

    const html = `<html><script src="/a.js"></script><script src="/b.js"></script></html>`;
    expect(await checkSourceMaps(html, `${site.origin}/`)).toHaveLength(1);
  });
});

describe("checkSourceMaps — does not invent one", () => {
  it("ignores a catch-all that answers 200 with the app shell", async () => {
    // A single-page app routes every unknown path to index.html, so
    // /assets/app.js.map comes back 200 with HTML. That is not a source map.
    serve({
      "/assets/app.js.map": {
        body: "<!doctype html><html><title>My App</title><body>…</body></html>",
        ct: "text/html",
      },
      "/assets/app.js": { body: "console.log(1)", ct: "application/javascript" },
    });

    expect(await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`)).toEqual([]);
  });

  it("ignores a JSON error page served at the .map path", async () => {
    serve({
      "/assets/app.js.map": { body: JSON.stringify({ error: "not_found", status: 404 }) },
      "/assets/app.js": { body: "console.log(1)", ct: "application/javascript" },
    });

    expect(await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`)).toEqual([]);
  });

  it("ignores JSON that has no sources array", async () => {
    serve({
      "/assets/app.js.map": { body: JSON.stringify({ version: 3, mappings: "AAAA" }) },
      "/assets/app.js": { body: "console.log(1)", ct: "application/javascript" },
    });

    expect(await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`)).toEqual([]);
  });

  it.skipIf(!OTHER_HOST_RESOLVES)("does not follow a script hosted on another host (a CDN)", async () => {
    // Libraries on a CDN publish their maps on purpose. They are not the
    // operator's source code and the operator cannot unpublish them.
    serve({ "/npm/lib/lib.js.map": { body: realMap } });

    const html = page(`http://cdn.lvh.me:${site.port}/npm/lib/lib.js`);
    expect(await checkSourceMaps(html, `${site.origin}/`)).toEqual([]);
    expect(site.seen.filter((r) => r.host.startsWith("cdn.lvh.me"))).toEqual([]);
  });

  it("ignores an inline data: URI map, which is not a server exposure", async () => {
    serve({
      "/app.js": {
        body: "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==",
        ct: "application/javascript",
      },
    });

    expect(await checkSourceMaps(page("/app.js"), `${site.origin}/`)).toEqual([]);
  });

  it.skipIf(!OTHER_HOST_RESOLVES)("does not follow a sourceMappingURL pointing at another host", async () => {
    serve({
      "/app.js": {
        body: `//# sourceMappingURL=http://cdn.lvh.me:${site.port}/maps/app.map`,
        ct: "application/javascript",
      },
      "/maps/app.map": { body: realMap },
    });

    expect(await checkSourceMaps(page("/app.js"), `${site.origin}/`)).toEqual([]);
    expect(site.seen.filter((r) => r.host.startsWith("cdn.lvh.me"))).toEqual([]);
  });

  it("reports nothing when the page loads no scripts", async () => {
    serve({});
    expect(await checkSourceMaps("<html><body>no scripts</body></html>", `${site.origin}/`)).toEqual([]);
  });
});

describe("checkSourceMaps — evidence matches what was actually found", () => {
  it("does not claim sourcesContent when the map carries only paths", async () => {
    // archive.org's exposed map is a vendored polyfill with no sourcesContent:
    // it leaks file paths, not the operator's source. The evidence must not
    // say otherwise, whatever the finding is titled.
    serve({
      "/assets/app.js.map": { body: mapWithoutContent },
    });

    const vulns = await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.evidence).toMatch(/Source files mapped: 2/);
    expect(vulns[0]!.evidence).not.toMatch(/Full sourcesContent|Full source content/);
  });

  it("titles and rates a names-only map as file names exposed, not full source", async () => {
    serve({ "/assets/app.js.map": { body: mapWithoutContent } });
    const [v] = await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`);
    expect(v!.name).toMatch(/Source File Names Only/);
    expect(v!.name).not.toMatch(/Full Source Code/);
    expect(v!.severity).toBe("low");
  });

  it("treats null or empty sourcesContent placeholders as names-only", async () => {
    const body = JSON.stringify({ version: 3, sources: ["a.ts"], sourcesContent: [null], mappings: "AAAA" });
    serve({ "/assets/app.js.map": { body } });
    const [v] = await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`);
    expect(v!.severity).toBe("low");
  });

  it("keeps High and the full-source title when sourcesContent is embedded", async () => {
    serve({ "/assets/app.js.map": { body: realMap } });
    const [v] = await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`);
    expect(v!.name).toMatch(/Full Source Code Accessible/);
    expect(v!.severity).toBe("high");
  });
});

/**
 * A map is only as sensitive as what it embeds. Found by the 2026-09-30 sweep: fastly.com's map is
 * 125 node_modules files and one Sentry config; archive.org's is a vendored copy of a public library.
 * Both were High "Full Source Code Accessible".
 */
describe("checkSourceMaps — rated by whose code the map contains", () => {
  const mapOf = (sources: string[]) =>
    JSON.stringify({ version: 3, sources, sourcesContent: sources.map((s) => `// ${s}`), mappings: "AAAA" });
  const libs = (n: number) => Array.from({ length: n }, (_, i) => `../../node_modules/.pnpm/pkg${i}@1.0.0/node_modules/pkg${i}/index.js`);

  it("rates a map that is nearly all node_modules as Low, and says how much is the site's own", async () => {
    serve({ "/_astro/page.js.map": { body: mapOf([...libs(125), "../../sentry.client.config.js"]) } });
    const [v] = await checkSourceMaps(page("/_astro/page.js"), `${site.origin}/`);
    expect(v!.severity).toBe("low");
    expect(v!.name).toMatch(/Third-Party Library Code/);
    expect(v!.name).not.toMatch(/Full Source Code/);
    expect(v!.evidence).toMatch(/126, of which the site's own: 1/);
    expect(v!.evidence).toMatch(/sentry\.client\.config\.js/);
  });

  it("rates a map served from a vendor directory as Low even when its paths look like source", async () => {
    serve({
      "/assets/vendor/lit/polyfill-support.js.map": {
        body: mapOf(["../reactive-element/src/polyfill-support.ts", "../lit-html/src/polyfill-support.ts", "../lit-element/src/polyfill-support.ts"]),
      },
    });
    const [v] = await checkSourceMaps(page("/assets/vendor/lit/polyfill-support.js"), `${site.origin}/`);
    expect(v!.severity).toBe("low");
    expect(v!.evidence).toMatch(/site's own: 0/);
  });

  it("keeps High when a real share of the map is the site's own code, even inside a large bundle", async () => {
    const own = Array.from({ length: 20 }, (_, i) => `../../app/components/Thing${i}.vue`);
    serve({ "/_nuxt/entry.js.map": { body: mapOf([...libs(281), ...own]) } });
    const [v] = await checkSourceMaps(page("/_nuxt/entry.js"), `${site.origin}/`);
    expect(v!.severity).toBe("high");
    expect(v!.name).toMatch(/Full Source Code Accessible/);
  });

  it("keeps High for a small app whose whole map is its own code", async () => {
    serve({ "/assets/app.js.map": { body: mapOf(["src/main.ts", "src/auth.ts"]) } });
    const [v] = await checkSourceMaps(page("/assets/app.js"), `${site.origin}/`);
    expect(v!.severity).toBe("high");
  });

  it("reports both when a page exposes an application map and a library map", async () => {
    serve({
      "/app.js.map": { body: mapOf(["src/main.ts", "src/auth.ts", "src/api.ts"]) },
      "/vendor/lib.js.map": { body: mapOf(["src/lib.ts"]) },
    });
    const html = `<html><script src="/app.js"></script><script src="/vendor/lib.js"></script></html>`;
    const vs = await checkSourceMaps(html, `${site.origin}/`);
    expect(vs.map((v) => v.severity).sort()).toEqual(["high", "low"]);
  });
});
