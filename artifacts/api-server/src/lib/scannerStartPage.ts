/**
 * The scan's first request and, for a JavaScript app, the headless render of it. The only request whose
 * failure ends the scan. Split from scanner.ts, which analyses what this returns.
 */
import { scanFetchOrThrow } from "./http";
import { isSpa, renderPage } from "./browser";
import { detectChallengePage } from "./challengePage.js";
import type { ObservedRequest } from "./apiRuntime";

const FETCH_TIMEOUT_MS = 20_000;

export async function loadStartPage(targetUrl: string) {
  // The only request whose failure ends the scan, so it is the only one that
  // throws rather than returning null — the underlying reason is what the user
  // needs to see when a target is unreachable.
  let initial;
  try {
    initial = await scanFetchOrThrow(targetUrl, {
      timeoutMs: FETCH_TIMEOUT_MS,
      headers: {
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to reach target URL: ${msg}`);
  }

  let finalUrl = initial.finalUrl || targetUrl;
  let html = initial.body;

  // Keys arrive lowercased from the shared client. Every lookup already goes
  // through the case-insensitive helper above, so this is a no-op for callers.
  const rawHeaders: Record<string, string> = { ...initial.headers };

  // ── SPA detection + headless rendering ────────────────────────────────────
  // If the server returned a JS-shell SPA (empty <div id="root"> etc.), re-fetch
  // via headless browser so content analysis operates on the fully-rendered DOM.
  // HTTP security headers stay from the raw fetch above — they're identical.
  let renderedWithBrowser = false;
  let observedRequests: ObservedRequest[] = [];
  let renderRejected: string | undefined;
  if (isSpa(html)) {
    const rendered = await renderPage(finalUrl).catch(() => null);
    // The browser can be answered differently from the plain fetch: a proxy error page, or a bot
    // challenge served only to headless Chrome. Analysing that page would replace the site's own
    // content, silently dropping every finding that reads it, so a render that failed where the
    // plain fetch did not is set aside and said so.
    // A challenge can also come back as HTTP 200 (Cloudflare's managed challenge to some clients,
    // Vercel's checkpoint), so the rendered page is checked for one as well as for its status.
    const renderedChallenge = rendered ? detectChallengePage(rendered.status, rendered.html, rendered.headers) : null;
    const initialChallenge = detectChallengePage(initial.status, html, rawHeaders);
    if (rendered && rendered.status >= 400 && rendered.status !== initial.status) {
      renderRejected = `the headless browser was answered with HTTP ${rendered.status} where the plain request got HTTP ${initial.status}`;
    } else if (rendered && renderedChallenge?.isChallenge && !initialChallenge.isChallenge) {
      renderRejected = `the headless browser was shown a bot-protection challenge (${renderedChallenge.signal}) that the plain request was not`;
    } else if (rendered) {
      html = rendered.html;
      finalUrl = rendered.finalUrl || finalUrl;
      renderedWithBrowser = true;
      observedRequests = rendered.observed;
    }
  }

  return { initial, finalUrl, html, rawHeaders, renderedWithBrowser, observedRequests, renderRejected };
}
