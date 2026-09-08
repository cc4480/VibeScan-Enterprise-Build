/**
 * Headless browser manager for SPA rendering.
 *
 * Wraps Playwright/Chromium to render JavaScript-heavy single-page apps
 * before running security analysis. Falls back to raw fetch gracefully when
 * the browser is unavailable (no Playwright install, no Chromium, or any
 * launch failure).
 *
 * Lifecycle:
 *   startWorker() → initBrowser()   (one browser process, shared across jobs)
 *   process exit  → closeBrowser()
 *
 * Each scan gets its own BrowserContext (isolated cookies/storage/network).
 * Pages are closed immediately after rendering.
 */

import { logger } from "./logger";
import { CHROMIUM_ARGS } from "./browserArgs";
import { getScanHttpContext } from "./http";

// ── Chromium executable resolution ──────────────────────────────────────────
//
// We intentionally do NOT pass an explicit executablePath. Playwright resolves
// the Chromium build that matches the installed Playwright version on its own,
// honouring PLAYWRIGHT_BROWSERS_PATH when it is set. A previous version hardcoded
// a browser revision into the path ("chromium-1194/…"), which silently broke
// launch whenever the Playwright version — and thus the required revision —
// changed (e.g. Playwright 1.62 needs revision 1234, not 1194), disabling SPA
// rendering in production with no error surfaced to the user.

// ── Browser singleton ────────────────────────────────────────────────────────

// Lazy-imported so the module loads even when playwright is not installed.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _chromium: any | null = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _browser: any | null = null;

async function getChromium() {
  if (_chromium) return _chromium;
  try {
    const pw = await import("playwright");
    _chromium = pw.chromium;
    return _chromium;
  } catch {
    return null;
  }
}

function proxyConfig(): { server: string } | undefined {
  const url = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
  return url ? { server: url } : undefined;
}

export async function initBrowser(): Promise<void> {
  const chromium = await getChromium();
  if (!chromium) {
    logger.warn("playwright package not found — SPA headless rendering disabled");
    return;
  }

  const proxy = proxyConfig();

  try {
    _browser = await chromium.launch({
      headless: true,
      proxy,
      args: [...CHROMIUM_ARGS],
    });
    logger.info(
      { proxy: proxy?.server ?? "none" },
      "Headless browser initialised — SPA rendering enabled",
    );
  } catch (err) {
    logger.warn({ err }, "Failed to launch headless browser — SPA rendering disabled");
    _browser = null;
  }
}

export async function closeBrowser(): Promise<void> {
  if (_browser) {
    await (_browser as { close(): Promise<void> }).close().catch(() => {});
    _browser = null;
    logger.info("Headless browser closed");
  }
}

// ── SPA detection ────────────────────────────────────────────────────────────

/**
 * Returns true when the raw server HTML is a JavaScript-rendered SPA shell
 * that will have little visible content until JS executes.
 *
 * Heuristics (any one match → SPA):
 *  1. Empty root mount point  <div id="root"></div>  (React, Vue, etc.)
 *  2. Body text < 200 chars with ≥2 bundled script tags (Create React App, Vite)
 *  3. Explicit CRA / Vite / webpack chunk URL pattern alongside empty root
 */
export function isSpa(rawHtml: string): boolean {
  const s = rawHtml.slice(0, 30_000);

  // 1. Empty SPA root mount point
  if (
    /<div[^>]+id=["'](?:root|app|__next|vue-app|ng-app|main|application)["'][^>]*>\s*<\/div>/i.test(s)
  ) {
    return true;
  }

  // 2. Tiny body with script bundles
  const bodyMatch = /<body[^>]*>([\s\S]*?)<\/body>/i.exec(s);
  if (bodyMatch) {
    const bodyContent = bodyMatch[1];
    const bodyText = bodyContent.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
    const scriptCount = (bodyContent.match(/<script/gi) ?? []).length;
    if (bodyText.length < 300 && scriptCount >= 2) return true;
  }

  // 3. CRA / Vite fingerprints combined with root div (even non-empty)
  if (
    /id=["']root["']/.test(s) &&
    /\/static\/js\/main\.|\/assets\/index-[a-z0-9]+\.js/i.test(s)
  ) {
    return true;
  }

  return false;
}

// ── Page rendering ────────────────────────────────────────────────────────────

export interface RenderedPage {
  /** Fully rendered DOM HTML (post JS execution) */
  html: string;
  /** HTTP response headers from the main document request */
  headers: Record<string, string>;
  /** Cookies as Set-Cookie strings (reconstructed from the page context) */
  setCookies: string[];
  /** HTTP status code of the main document response */
  status: number;
  /** Final URL after all redirects */
  finalUrl: string;
}

const NAVIGATION_TIMEOUT_MS = 25_000;
const SETTLE_MS = 1_500; // extra wait after networkidle for deferred renders

/**
 * Render a URL using the headless browser and return the post-JS-execution
 * HTML along with response metadata.
 *
 * Returns null when:
 *  - Browser was not launched (no Playwright / no Chromium)
 *  - Navigation fails for any reason (network error, timeout, bad URL)
 *
 * Callers should fall back to raw `fetch()` on null.
 */
/** A cookie as Playwright reports it. Only the fields we serialise. */
export interface BrowserCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: string;
}

/**
 * Turn browser-context cookies into Set-Cookie strings for the scanned origin.
 *
 * Filters to first-party cookies. A browser context accumulates cookies from
 * every origin the page touches — Google, ad networks, embedded widgets — and
 * the scanned site is not responsible for any of them. Attributing them
 * produced a "session cookie SID missing Secure" finding against bestbuy.com,
 * whose own server sends no Set-Cookie header at all; SID is a Google cookie.
 *
 * A cookie belongs to the target when its domain is the target host or a parent
 * of it, matching how the browser decides what to send.
 */
export function toSetCookieStrings(cookies: BrowserCookie[], targetUrl: string): string[] {
  let host: string;
  try {
    host = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return [];
  }

  return cookies
    .filter((c) => {
      const domain = (c.domain ?? "").replace(/^\./, "").toLowerCase();
      if (!domain) return true; // host-only cookie from this page
      return host === domain || host.endsWith(`.${domain}`);
    })
    .map((c) => {
      let s = `${c.name}=${c.value}`;
      if (c.secure) s += "; Secure";
      if (c.httpOnly) s += "; HttpOnly";
      if (c.sameSite && c.sameSite !== "None") s += `; SameSite=${c.sameSite}`;
      if (c.path) s += `; Path=${c.path}`;
      return s;
    });
}

export async function renderPage(url: string): Promise<RenderedPage | null> {
  if (!_browser) return null;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let context: any | null = null;
  try {
    // Carry the scan's credentials into the browser context.
    //
    // Without this an authenticated scan renders the *logged-out* page: the
    // browser context is isolated from the HTTP client's session, so an SPA
    // target would be analysed as its sign-in screen while every other probe
    // saw the real application. That failure is silent, which makes it worse
    // than an error — the report would look clean because nothing was seen.
    const ctx = getScanHttpContext();
    const credentials = ctx?.credentials;
    const inScope = ctx?.scope.includes(url) ?? false;

    const extraHTTPHeaders: Record<string, string> = {};
    if (credentials && inScope) {
      if (credentials.cookie) extraHTTPHeaders["Cookie"] = credentials.cookie;
      Object.assign(extraHTTPHeaders, credentials.headers ?? {});
    }

    context = await (_browser as {
      newContext(opts: {
        userAgent: string;
        ignoreHTTPSErrors: boolean;
        javaScriptEnabled: boolean;
        extraHTTPHeaders?: Record<string, string>;
      }): Promise<unknown>;
    }).newContext({
      userAgent:
        "Mozilla/5.0 (compatible; VibeScan-Security-Bot/1.0; +https://secscan.us/bot)",
      ignoreHTTPSErrors: false,
      javaScriptEnabled: true,
      ...(Object.keys(extraHTTPHeaders).length > 0 ? { extraHTTPHeaders } : {}),
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const page: any = await (context as any).newPage();
    page.setDefaultNavigationTimeout(NAVIGATION_TIMEOUT_MS);
    page.setDefaultTimeout(NAVIGATION_TIMEOUT_MS);

    const responseHeaders: Record<string, string> = {};
    let responseStatus = 200;
    let responseUrl = url;

    // Capture HTTP response headers from the main document only
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    page.on("response", (resp: any) => {
      if (resp.request().resourceType() === "document") {
        responseStatus = resp.status();
        responseUrl = resp.url();
        const hdrs: Record<string, string> = resp.headers();
        for (const [k, v] of Object.entries(hdrs)) {
          responseHeaders[k.toLowerCase()] = v;
        }
      }
    });

    // Try networkidle first (best for SPAs that fetch data on mount);
    // fall back to domcontentloaded + settle delay for pages that keep
    // polling and never reach idle.
    try {
      await page.goto(url, { waitUntil: "networkidle", timeout: NAVIGATION_TIMEOUT_MS });
    } catch {
      try {
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: NAVIGATION_TIMEOUT_MS });
        await page.waitForTimeout(SETTLE_MS);
      } catch {
        // If even domcontentloaded fails, give up and let the caller fall back
        return null;
      }
    }

    const finalUrl: string = page.url();
    const html: string = await page.content();

    // Reconstruct Set-Cookie strings from the page's cookies.
    //
    // Scoped to the page's own URL deliberately. `context.cookies()` with no
    // argument returns EVERY cookie in the browser context — including ones set
    // by Google, ad networks, embedded widgets and any other third party the
    // page loaded. Attributing those to the scanned site produces findings its
    // server never sent: bestbuy.com was reported as having a session cookie
    // "SID" missing the Secure flag, a Google cookie name, when bestbuy.com
    // returns no Set-Cookie header at all.
    //
    // Passing the URL filters to cookies that would actually be sent to this
    // origin, which is the only set the site is responsible for.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cookieObjects: BrowserCookie[] = await (context as any).cookies(finalUrl);
    const setCookies: string[] = toSetCookieStrings(cookieObjects, finalUrl);

    // Use the captured URL as final if navigation settled at a different path
    const effectiveFinalUrl = finalUrl || responseUrl || url;

    return {
      html,
      headers: responseHeaders,
      setCookies,
      status: responseStatus,
      finalUrl: effectiveFinalUrl,
    };
  } catch (err) {
    logger.warn({ err, url }, "Browser render failed — caller will fall back to fetch");
    return null;
  } finally {
    // Always close the context so the browser process doesn't accumulate pages
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (context as any)?.close().catch(() => {});
  }
}
