import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Page } from "playwright";
import { tokenInUrl } from "./url-token";
import { HAVE_CHROMIUM, bundleForBrowser, startBrowserLab, type BrowserLab } from "./browser.testkit";

/**
 * The address bar, history and location are a real Chromium page's own: the module is bundled as the app bundles it and
 * run in a page served from a local web server, and what it did is read back from the page.
 */

let lab: BrowserLab;
let code: string;

beforeAll(async () => {
  if (!HAVE_CHROMIUM) return;
  code = await bundleForBrowser("url-token.ts");
  lab = await startBrowserLab();
}, 60_000);
afterAll(async () => { await lab?.stop(); });

type Mod = { tokenInUrl(win?: Window): string; clearTokenFromUrl(win?: Window): void };
declare global { interface Window { mod: Mod } }

/** A page at `pathAndQuery` with the module loaded. */
async function open(pathAndQuery: string): Promise<Page> {
  const { page } = await lab.freshPage();
  await page.goto(`${lab.origin}${pathAndQuery}`);
  await page.addScriptTag({ content: code });
  return page;
}
/** Where the page is, and how many entries its history has. */
const where = (page: Page) => page.evaluate(() => ({ path: location.pathname + location.search + location.hash, entries: history.length }));

describe.skipIf(!HAVE_CHROMIUM)("tokenInUrl", () => {
  it("reads the token and leaves the address alone", async () => {
    const page = await open("/verify-email?token=abc123&x=1");
    const before = await where(page);
    expect(await page.evaluate(() => window.mod.tokenInUrl())).toBe("abc123");
    expect(await where(page)).toEqual(before);
  });

  it("returns an empty string when there is no token", async () => {
    const page = await open("/reset-password");
    expect(await page.evaluate(() => window.mod.tokenInUrl())).toBe("");
  });
});

describe("tokenInUrl with no window at all", () => {
  it("returns an empty string (server-side rendering, where there is no address bar)", () => {
    expect(typeof window).toBe("undefined");
    expect(tokenInUrl(undefined)).toBe("");
  });
});

describe.skipIf(!HAVE_CHROMIUM)("clearTokenFromUrl", () => {
  it("removes the token from the address bar, keeping other parameters and the hash, without adding a history entry", async () => {
    const page = await open("/reset-password?token=abc123&ref=mail#top");
    const before = await where(page);
    await page.evaluate(() => window.mod.clearTokenFromUrl());
    const after = await where(page);
    expect(after.path).toBe("/reset-password?ref=mail#top");
    expect(after.path).not.toContain("token");
    // replaceState swaps the entry; back would not return to an address with the token in it.
    expect(after.entries).toBe(before.entries);
  });

  it("is a no-op when there is no token", async () => {
    const page = await open("/reset-password?ref=mail");
    const before = await where(page);
    await page.evaluate(() => window.mod.clearTokenFromUrl());
    expect(await where(page)).toEqual(before);
  });

  it("does nothing the second time, so a React double-mount is harmless", async () => {
    const page = await open("/verify-email?token=abc123");
    await page.evaluate(() => window.mod.clearTokenFromUrl());
    const once = await where(page);
    await page.evaluate(() => window.mod.clearTokenFromUrl());
    expect(await where(page)).toEqual(once);
    expect(once.path).toBe("/verify-email");
  });
});
