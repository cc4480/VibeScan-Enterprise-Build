/**
 * A real browser for the tests of code that talks to the browser (localStorage, the address bar, history).
 *
 * The module under test is bundled exactly as the app would bundle it (esbuild) and loaded into a page of a real Chromium
 * served from a real local web server, so localStorage, location and history are the browser's own and not stand-ins. The
 * suite is skipped where Playwright's Chromium is not installed.
 */
import http from "node:http";
import { existsSync } from "node:fs";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright";
import { build } from "esbuild";

export const HAVE_CHROMIUM = (() => {
  try { return existsSync(chromium.executablePath()); } catch { return false; }
})();

/** The module at `entry` (relative to src/lib) as a script that puts its exports on `window[globalName]`. */
export async function bundleForBrowser(entry: string, globalName = "mod"): Promise<string> {
  const out = await build({
    entryPoints: [path.resolve(import.meta.dirname, entry)],
    bundle: true,
    write: false,
    format: "iife",
    globalName,
    platform: "browser",
    target: "es2022",
  });
  return out.outputFiles[0]!.text;
}

export interface BrowserLab {
  browser: Browser;
  /** http://127.0.0.1:PORT, a server that answers every path with an empty page. */
  origin: string;
  /** A page in its own context, so nothing it stores is seen by the next test. */
  freshPage(): Promise<{ page: Page; context: BrowserContext }>;
  stop(): Promise<void>;
}

export async function startBrowserLab(): Promise<BrowserLab> {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" }).end("<!doctype html><html><head><title>test page</title></head><body></body></html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const browser = await chromium.launch();
  return {
    browser,
    origin,
    freshPage: async () => {
      const context = await browser.newContext();
      return { context, page: await context.newPage() };
    },
    stop: async () => {
      await browser.close();
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
