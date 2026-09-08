import { describe, it, expect, afterEach, vi } from "vitest";
import { checkSourceMaps } from "./sourceMaps.js";

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

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

/** Serves specific URLs; anything else 404s, like a normal origin. */
function serve(routes: Record<string, { body: string; status?: number; ct?: string }>) {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const hit = routes[url];
    if (!hit) return new Response("Not Found", { status: 404 });
    return new Response(hit.body, {
      status: hit.status ?? 200,
      headers: { "content-type": hit.ct ?? "application/json" },
    });
  }) as typeof fetch;
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
      "https://example.com/assets/app.js.map": { body: realMap },
    });

    const vulns = await checkSourceMaps(page("/assets/app.js"), "https://example.com/");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("high");
    expect(vulns[0]!.cweId).toBe("CWE-540");
    expect(vulns[0]!.evidence).toMatch(/Source files mapped: 2/);
    expect(vulns[0]!.evidence).toMatch(/sourcesContent/);
  });

  it("follows a sourceMappingURL comment in the bundle trailer", async () => {
    serve({
      "https://example.com/assets/app.js": { body: "//# sourceMappingURL=app.abc123.map", ct: "application/javascript" },
      "https://example.com/assets/app.abc123.map": { body: realMap },
    });

    const vulns = await checkSourceMaps(page("/assets/app.js"), "https://example.com/");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.evidence).toMatch(/app\.abc123\.map/);
  });

  it("reports only once when several bundles expose maps", async () => {
    serve({
      "https://example.com/a.js.map": { body: realMap },
      "https://example.com/b.js.map": { body: realMap },
    });

    const html = `<html><script src="/a.js"></script><script src="/b.js"></script></html>`;
    expect(await checkSourceMaps(html, "https://example.com/")).toHaveLength(1);
  });
});

describe("checkSourceMaps — does not invent one", () => {
  it("ignores a catch-all that answers 200 with the app shell", async () => {
    // A single-page app routes every unknown path to index.html, so
    // /assets/app.js.map comes back 200 with HTML. That is not a source map.
    serve({
      "https://example.com/assets/app.js.map": {
        body: "<!doctype html><html><title>My App</title><body>…</body></html>",
        ct: "text/html",
      },
      "https://example.com/assets/app.js": { body: "console.log(1)", ct: "application/javascript" },
    });

    expect(await checkSourceMaps(page("/assets/app.js"), "https://example.com/")).toEqual([]);
  });

  it("ignores a JSON error page served at the .map path", async () => {
    serve({
      "https://example.com/assets/app.js.map": { body: JSON.stringify({ error: "not_found", status: 404 }) },
      "https://example.com/assets/app.js": { body: "console.log(1)", ct: "application/javascript" },
    });

    expect(await checkSourceMaps(page("/assets/app.js"), "https://example.com/")).toEqual([]);
  });

  it("ignores JSON that has no sources array", async () => {
    serve({
      "https://example.com/assets/app.js.map": { body: JSON.stringify({ version: 3, mappings: "AAAA" }) },
      "https://example.com/assets/app.js": { body: "console.log(1)", ct: "application/javascript" },
    });

    expect(await checkSourceMaps(page("/assets/app.js"), "https://example.com/")).toEqual([]);
  });

  it("does not follow a script hosted on a CDN", async () => {
    // Libraries on a CDN publish their maps on purpose. They are not the
    // operator's source code and the operator cannot unpublish them.
    serve({
      "https://cdn.jsdelivr.net/npm/lib/lib.js.map": { body: realMap },
    });

    const html = page("https://cdn.jsdelivr.net/npm/lib/lib.js");
    expect(await checkSourceMaps(html, "https://example.com/")).toEqual([]);
  });

  it("ignores an inline data: URI map, which is not a server exposure", async () => {
    serve({
      "https://example.com/app.js": {
        body: "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==",
        ct: "application/javascript",
      },
    });

    expect(await checkSourceMaps(page("/app.js"), "https://example.com/")).toEqual([]);
  });

  it("does not follow a sourceMappingURL pointing at another host", async () => {
    serve({
      "https://example.com/app.js": {
        body: "//# sourceMappingURL=https://maps.other-cdn.com/app.js.map",
        ct: "application/javascript",
      },
      "https://maps.other-cdn.com/app.js.map": { body: realMap },
    });

    expect(await checkSourceMaps(page("/app.js"), "https://example.com/")).toEqual([]);
  });

  it("reports nothing when the page loads no scripts", async () => {
    serve({});
    expect(await checkSourceMaps("<html><body>no scripts</body></html>", "https://example.com/")).toEqual([]);
  });
});

describe("checkSourceMaps — evidence matches what was actually found", () => {
  it("does not claim sourcesContent when the map carries only paths", async () => {
    // archive.org's exposed map is a vendored polyfill with no sourcesContent:
    // it leaks file paths, not the operator's source. The evidence must not
    // say otherwise, whatever the finding is titled.
    serve({
      "https://example.com/assets/app.js.map": { body: mapWithoutContent },
    });

    const vulns = await checkSourceMaps(page("/assets/app.js"), "https://example.com/");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.evidence).toMatch(/Source files mapped: 2/);
    expect(vulns[0]!.evidence).not.toMatch(/sourcesContent/);
  });
});
