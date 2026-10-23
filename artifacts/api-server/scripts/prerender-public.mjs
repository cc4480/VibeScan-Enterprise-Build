// Renders the public pages in headless Chromium and saves each page's markup, so the
// API server can send crawlers that run no JavaScript the real page instead of an
// empty <div id="root">. Run after the frontend build:
//
//   pnpm --filter @workspace/api-server run prerender
//
// It never fails the build: a missing browser, a page that does not settle or one
// that rendered an error just means that page is served the way it was before.
// Output: <frontend dist>/prerender/<name>.root.html — the inside of #root.
import { createServer } from "node:http";
import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dist = path.resolve(
  process.env.FRONTEND_STATIC_DIR ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "../../vibescan/dist/public"),
);

// route → file name. Keep in step with PRERENDERED in src/app.ts.
const PAGES = { "/": "home", "/learn": "learn", "/about": "about", "/bot": "bot", "/privacy": "privacy", "/terms": "terms" };

// The check pages (/learn/<id>) come from the list the frontend build wrote.
async function checkPages() {
  try {
    const list = JSON.parse(await readFile(path.join(dist, "prerender", "checks.json"), "utf8"));
    return Object.fromEntries(list.map((c) => [`/learn/${c.id}`, `learn-${c.id}`]));
  } catch {
    return {};
  }
}

const TYPES = {
  ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json",
  ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp",
  ".ico": "image/x-icon", ".mp4": "video/mp4", ".woff2": "font/woff2", ".txt": "text/plain", ".xml": "application/xml",
};

/** A page that failed to render must not be saved as if it were the page. */
const looksBroken = (html) => html.length < 2000 || /something went wrong|application error|page not found/i.test(html);

async function main() {
  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    console.warn("prerender: playwright is not installed — skipping");
    return;
  }

  // A tiny static server with the SPA fallback; the API is deliberately not running,
  // so each page renders in its signed-out state, which is what a crawler is.
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname.startsWith("/api/")) { res.writeHead(404).end(); return; }
    let file = path.join(dist, path.normalize(url.pathname));
    if (!file.startsWith(dist)) { res.writeHead(403).end(); return; }
    try {
      if ((await stat(file)).isDirectory()) file = path.join(file, "index.html");
      await stat(file);
    } catch {
      file = path.join(dist, "index.html");
    }
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "application/octet-stream" });
    res.end(await readFile(file));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;

  let browser;
  try {
    browser = await chromium.launch({ args: ["--no-sandbox"], executablePath: process.env.PRERENDER_CHROME_PATH || undefined });
    await mkdir(path.join(dist, "prerender"), { recursive: true });
    for (const [route, name] of Object.entries({ ...PAGES, ...(await checkPages()) })) {
      const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
      try {
        await page.goto(origin + route, { waitUntil: "load", timeout: 30_000 });
        await page.waitForSelector("#root h1", { timeout: 15_000 });
        await page.waitForTimeout(1500); // entrance animations
        const html = (await page.evaluate(() => document.getElementById("root")?.innerHTML ?? "")).trim();
        if (looksBroken(html)) throw new Error(`rendered ${html.length} bytes that look wrong`);
        await writeFile(path.join(dist, "prerender", `${name}.root.html`), html);
        console.log(`prerender: ${route} → ${name}.root.html (${html.length} bytes)`);
      } catch (err) {
        console.warn(`prerender: ${route} skipped — ${err instanceof Error ? err.message : err}`);
      } finally {
        await page.close();
      }
    }
  } catch (err) {
    console.warn(`prerender: could not run the browser — ${err instanceof Error ? err.message : err}`);
  } finally {
    await browser?.close();
    server.close();
  }
}

main().catch((err) => console.warn("prerender: skipped —", err instanceof Error ? err.message : err));
