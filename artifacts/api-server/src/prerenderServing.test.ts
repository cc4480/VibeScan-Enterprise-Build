import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import request from "supertest";

/**
 * The production page-serving path, end to end: the built shell, the prerendered
 * fragments and the check list, served by the real app. Each of these was once
 * correct in its own unit and still failed here — the home page came back as the
 * bare shell because express.static answered "/" before the prerender code ran.
 */
const SHELL =
  '<!doctype html><html><head><title>SecScan</title><meta name="description" content="x" />' +
  '<meta name="robots" content="index, follow" /><link rel="canonical" href="https://secscan.us/" />' +
  '</head><body><div id="root"></div><script type="module" src="/assets/a.js"></script></body></html>';

let dir: string;
let app: import("express").Express;

beforeAll(async () => {
  dir = mkdtempSync(path.join(tmpdir(), "secscan-static-"));
  mkdirSync(path.join(dir, "prerender"));
  writeFileSync(path.join(dir, "index.html"), SHELL);
  writeFileSync(path.join(dir, "prerender", "home.root.html"), "<h1>Home page</h1>");
  writeFileSync(path.join(dir, "prerender", "about.root.html"), "<h1>About page</h1>");
  writeFileSync(path.join(dir, "prerender", "learn-hsts.root.html"), "<h1>HSTS page</h1>");
  writeFileSync(
    path.join(dir, "prerender", "checks.json"),
    JSON.stringify([
      { id: "hsts", title: "HSTS: what it is — SecScan.us", description: "d", name: "HSTS", what: "w", fix: "f" },
      { id: "csp-missing", title: "CSP — SecScan.us", description: "d", name: "CSP", what: "w", fix: "f" },
    ]),
  );
  vi.stubEnv("NODE_ENV", "production");
  vi.stubEnv("FRONTEND_STATIC_DIR", dir);
  vi.resetModules();
  app = (await import("./app")).default;
});

afterAll(() => {
  vi.unstubAllEnvs();
  rmSync(dir, { recursive: true, force: true });
});

describe("serving the prerendered public pages", () => {
  it("puts the prerendered home page in the root at /", async () => {
    const res = await request(app).get("/");
    expect(res.status).toBe(200);
    expect(res.text).toContain('<div id="root"><h1>Home page</h1></div>');
  });

  it("does the same for a page with its own metadata, keeping that metadata", async () => {
    const res = await request(app).get("/about");
    expect(res.status).toBe(200);
    expect(res.text).toContain('<div id="root"><h1>About page</h1></div>');
    expect(res.text).toContain('<link rel="canonical" href="https://secscan.us/about" />');
  });

  it("serves a documented check with its own title and prerendered body", async () => {
    const res = await request(app).get("/learn/hsts");
    expect(res.status).toBe(200);
    expect(res.text).toContain("<title>HSTS: what it is — SecScan.us</title>");
    expect(res.text).toContain('<div id="root"><h1>HSTS page</h1></div>');
  });

  it("serves a documented check that has no prerendered body, as the plain shell with its metadata", async () => {
    const res = await request(app).get("/learn/csp-missing");
    expect(res.status).toBe(200);
    expect(res.text).toContain("<title>CSP — SecScan.us</title>");
    expect(res.text).toContain('<div id="root"></div>');
  });

  it("answers 404 for an id that is not a documented check", async () => {
    const res = await request(app).get("/learn/not-a-check");
    expect(res.status).toBe(404);
    expect(res.text).not.toContain('<div id="root">');
  });

  it("does not serve the build's own fragments or check list as pages", async () => {
    expect((await request(app).get("/prerender/home.root.html")).status).toBe(404);
    expect((await request(app).get("/prerender/checks.json")).status).toBe(404);
  });
});

describe("caching of the pages themselves", () => {
  it("re-checks every page on each visit, so a deploy is seen at once instead of an old page loading the old app", async () => {
    for (const path of ["/", "/about", "/learn/hsts", "/learn/csp-missing", "/dashboard"]) {
      const res = await request(app).get(path);
      expect(res.status, path).toBe(200);
      expect(res.headers["cache-control"], path).toBe("no-cache");
    }
  });
});
