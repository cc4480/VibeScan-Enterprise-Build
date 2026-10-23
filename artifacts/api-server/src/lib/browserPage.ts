/** SPA detection and the rendered-page and cookie shapes. */
import { type ObservedRequest } from "./apiRuntime";

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
  /** The fetch/XHR requests the page made while rendering (shape only, see apiRuntime.ts) */
  observed: ObservedRequest[];
}

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
