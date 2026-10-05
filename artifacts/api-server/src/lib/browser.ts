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

import { guardBrowser } from "./browserGuard";
import { logger } from "./logger";
import { SCANNER_USER_AGENT } from "./appOrigin";
import { launchChromium } from "./launchChromium";
import { browserProxy, closeBrowserProxy } from "./browserProxy";
import { getScanHttpContext } from "./http";
import { jsonBodyKeys, type ObservedRequest } from "./apiRuntime";
import { type RenderedPage, type BrowserCookie, toSetCookieStrings } from "./browserPage";
export { isSpa, toSetCookieStrings } from "./browserPage";
export type { RenderedPage, BrowserCookie } from "./browserPage";

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

export async function initBrowser(): Promise<void> {
  const chromium = await getChromium();
  if (!chromium) {
    logger.warn("playwright package not found — SPA headless rendering disabled");
    return;
  }

  const proxy = await browserProxy();

  try {
    _browser = await launchChromium(chromium, proxy);
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
  await closeBrowserProxy();
}

const NAVIGATION_TIMEOUT_MS = 25_000;
const SETTLE_MS = 1_500; // extra wait after networkidle for deferred renders

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

    // Sent only to requests in scope, by the guard below. As context-wide extraHTTPHeaders they went to
    // every host the page loaded from, including third parties and redirect targets.
    const credentialHeaders: Record<string, string> = {};
    if (credentials && inScope) {
      if (credentials.cookie) credentialHeaders["Cookie"] = credentials.cookie;
      Object.assign(credentialHeaders, credentials.headers ?? {});
    }

    context = await (_browser as {
      newContext(opts: {
        userAgent: string;
        ignoreHTTPSErrors: boolean;
        javaScriptEnabled: boolean;
      }): Promise<unknown>;
    }).newContext({
      // The same User-Agent as every other scan request. This was a separate, older string
      // ("VibeScan-Security-Bot"), so a site that allowed the scanner by the name /bot documents
      // ("SecScan-Security-Bot") let the plain requests through and challenged the browser.
      userAgent: SCANNER_USER_AGENT,
      ignoreHTTPSErrors: false,
      javaScriptEnabled: true,
    });
    // Every request the page makes, redirect hops included, must be to a public address, and the
    // credentials go only where the scan is in scope.
    await guardBrowser(context as never, {
      credentialHeaders,
      inScope: (u) => ctx?.scope.includes(u) ?? false,
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const page: any = await (context as any).newPage();
    page.setDefaultNavigationTimeout(NAVIGATION_TIMEOUT_MS);
    page.setDefaultTimeout(NAVIGATION_TIMEOUT_MS);

    const responseHeaders: Record<string, string> = {};
    let responseStatus = 200;
    let responseUrl = url;

    // The page's own API calls, as the browser makes them. Method, URL and body key names
    // only; capped so a chatty page cannot grow this without bound.
    const observed: ObservedRequest[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    page.on("request", (req: any) => {
      const type = req.resourceType();
      if ((type === "fetch" || type === "xhr") && observed.length < 200) {
        observed.push({ method: req.method(), url: req.url(), bodyKeys: jsonBodyKeys(req.postData()) });
      }
    });

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
      observed,
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