import { scanFetch } from "./http";


/**
 * Checks whether a hostname appears to be on the HSTS preload list.
 *
 * Uses the hstspreload.org submission-tracking API. Note: this API only knows
 * about domains submitted through their website. Domains hardcoded in Chrome's
 * preload list (google.com, youtube.com, etc.) are not tracked there and will
 * return "unknown". For those, we fall back to a behavioral signal: if the
 * HTTP version of the domain serves content without redirecting to HTTPS, the
 * site is likely relying on browser preloading.
 *
 * Returns true to SUPPRESS the HSTS finding; false to allow it (at MEDIUM).
 * Always fails-safe: any network error returns false so the check still runs.
 */
// Domains hardcoded in Chrome's built-in HSTS preload list that are NOT
// tracked by hstspreload.org's submission API (which only knows about
// user-submitted entries, not Chrome's built-in set).
const CHROME_BUILTIN_PRELOADED = new Set([
  "google.com", "youtube.com", "gmail.com", "android.com", "appspot.com",
  "blogger.com", "chromium.org", "googleapis.com", "googlesyndication.com",
  "googleusercontent.com", "gstatic.com", "ytimg.com", "doubleclick.net",
  "apple.com", "icloud.com", "github.com", "github.io", "githubusercontent.com",
  "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
  "linkedin.com", "microsoft.com", "live.com", "outlook.com", "office.com",
  "paypal.com", "amazon.com", "stripe.com", "cloudflare.com",
  "wordpress.com", "shopify.com", "dropbox.com", "box.com",
  "tumblr.com", "medium.com", "reddit.com", "wikipedia.org",
]);

export async function isHstsPreloaded(hostname: string): Promise<boolean> {
  const apex = hostname.replace(/^www\./, "");

  // Fast path: known Chrome built-in preloaded domains not tracked by hstspreload.org
  if (CHROME_BUILTIN_PRELOADED.has(apex)) return true;

  // ── hstspreload.org tracking API ─────────────────────────────────────────
  // This API only tracks domains submitted via their form. Domains natively
  // hardcoded in Chrome (google.com, youtube.com, etc.) return "unknown".
  let apiKnows = false;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5_000);
    const res = await fetch(
      `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(apex)}`,
      { signal: ctrl.signal },
    );
    clearTimeout(timer);
    if (res.ok) {
      const json = (await res.json()) as { status?: string };
      if (json.status === "preloaded") return true;  // confirmed on list
      if (json.status === "pending")   return false; // submitted, not yet live
      // status === "unknown" — domain may still be natively preloaded; fall through
      apiKnows = json.status === "preloaded" || json.status === "pending";
    }
  } catch { /* fall through */ }

  if (apiKnows) return false;

  // ── Behavioral fallback for natively preloaded domains ───────────────────
  // If http:// traffic automatically upgrades to https://, the domain is
  // enforcing HTTPS one way or another — suppress the HSTS finding.
  const httpRes = await scanFetch(`http://${apex}/`, { timeoutMs: 5_000 });
  if (httpRes?.finalUrl.startsWith("https://")) return true;

  return false;
}
