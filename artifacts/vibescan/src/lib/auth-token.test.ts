import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Page } from "playwright";
import { HAVE_CHROMIUM, bundleForBrowser, startBrowserLab, type BrowserLab } from "./browser.testkit";

/**
 * The anonymous identity.
 *
 * This UUID *is* the user as far as the API is concerned, so the behaviour that
 * matters is stability: a token that changed between calls would silently strip
 * someone of their scan history, and one that failed to persist would do the
 * same on the next page load.
 *
 * The module runs in a real Chromium page, against the browser's own localStorage. Loading the module again in the same
 * page after a reload is what "a fresh module, same storage" means to a visitor.
 */

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY = "vibescan_client_token";

let lab: BrowserLab;
let code: string;

beforeAll(async () => {
  if (!HAVE_CHROMIUM) return;
  code = await bundleForBrowser("auth-token.ts");
  lab = await startBrowserLab();
}, 60_000);
afterAll(async () => { await lab?.stop(); });

type Mod = { getOrCreateToken(): string; getAuthHeaders(): { Authorization: string } };
declare global { interface Window { mod: Mod } }

/** A page on the test origin with the module loaded fresh. */
async function open(): Promise<Page> {
  const { page } = await lab.freshPage();
  await page.goto(`${lab.origin}/`);
  return page;
}
const load = (page: Page) => page.addScriptTag({ content: code });
const token = (page: Page) => page.evaluate(() => window.mod.getOrCreateToken());

describe.skipIf(!HAVE_CHROMIUM)("getOrCreateToken", () => {
  it("mints a v4 UUID on first use", async () => {
    const page = await open();
    await load(page);
    expect(await token(page)).toMatch(UUID_V4);
  });

  it("returns the same token on every call", async () => {
    const page = await open();
    await load(page);
    const [a, b] = await page.evaluate(() => [window.mod.getOrCreateToken(), window.mod.getOrCreateToken()]);
    expect(a).toBe(b);
  });

  it("persists it, so a reload keeps the same identity", async () => {
    const page = await open();
    await load(page);
    const first = await token(page);
    expect(await page.evaluate((k) => localStorage.getItem(k), KEY)).toBe(first);

    // The page is loaded again: a fresh module, the same storage.
    await page.reload();
    await load(page);
    expect(await token(page)).toBe(first);
  });

  it("reuses an existing valid token rather than replacing it", async () => {
    const existing = "3b241101-e2bb-4255-8caf-4136c566a962";
    const page = await open();
    await page.evaluate(([k, v]) => localStorage.setItem(k!, v!), [KEY, existing]);
    await load(page);
    expect(await token(page)).toBe(existing);
  });

  it("replaces a stored value that is not a valid UUID", async () => {
    // A corrupt entry must not be sent as an identity: the API rejects
    // anything that is not a v4 UUID, which would look like being logged out.
    const page = await open();
    await page.evaluate((k) => localStorage.setItem(k, "not-a-uuid"), KEY);
    await load(page);
    const minted = await token(page);
    expect(minted).toMatch(UUID_V4);
    expect(await page.evaluate((k) => localStorage.getItem(k), KEY)).toBe(minted);
  });

  it("stays stable when localStorage cannot be written", async () => {
    // Private browsing and storage-blocking settings both do this. Falling back
    // to memory keeps the identity stable for the life of the page rather than
    // minting a new user on every call. Here the storage is genuinely full.
    const page = await open();
    await page.evaluate(() => {
      const chunk = "x".repeat(1 << 20);
      try { for (let i = 0; ; i++) localStorage.setItem(`filler${i}`, chunk); } catch { /* full */ }
    });
    expect(await page.evaluate(() => { try { localStorage.setItem("probe", "1".repeat(1 << 20)); return "writable"; } catch { return "full"; } })).toBe("full");
    await load(page);
    const minted = await token(page);
    expect(minted).toMatch(UUID_V4);
    expect(await token(page)).toBe(minted);
  });

  it("stays stable when localStorage cannot be read or written", async () => {
    // A sandboxed frame has no origin, and the browser denies it localStorage altogether, for reading as well as writing.
    const page = await open();
    await page.evaluate(() => {
      document.body.innerHTML = '<iframe id="sb" sandbox="allow-scripts" srcdoc="<!doctype html><title>sandboxed</title>"></iframe>';
    });
    const frame = await (await page.waitForSelector("#sb")).contentFrame();
    expect(frame).not.toBeNull();
    expect(await frame!.evaluate(() => { try { localStorage.getItem("x"); return "readable"; } catch { return "denied"; } })).toBe("denied");
    await frame!.addScriptTag({ content: code });
    const inFrame = () => frame!.evaluate(() => window.mod.getOrCreateToken());
    const minted = await inFrame();
    expect(minted).toMatch(UUID_V4);
    expect(await inFrame()).toBe(minted);
  });
});

describe.skipIf(!HAVE_CHROMIUM)("getAuthHeaders", () => {
  it("produces a bearer header carrying the token", async () => {
    const page = await open();
    await load(page);
    const t = await token(page);
    expect(await page.evaluate(() => window.mod.getAuthHeaders())).toEqual({ Authorization: `Bearer ${t}` });
  });
});
