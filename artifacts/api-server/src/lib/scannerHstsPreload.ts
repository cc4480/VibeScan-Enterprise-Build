import { isIP } from "node:net";

/** The preload list's status API. HSTS_PRELOAD_API_URL points it elsewhere (tests run a server of their own); read per call. */
export function hstsPreloadApiUrl(): string {
  return process.env["HSTS_PRELOAD_API_URL"] || "https://hstspreload.org/api/v2/status";
}

/** Names that cannot be on a public preload list, so there is nothing to ask about and no reason to send them anywhere. */
const NEVER_PRELOADED = /(^|\.)(local|localhost|internal|intranet|lan|home|corp|test|example|invalid)$/i;

/**
 * Whether browsers already treat this host as HTTPS-only before the first request, because it is on the
 * HSTS preload list that ships inside every major browser. That is what makes the Strict-Transport-Security
 * header optional for the host, so only a preloaded host is spared the "Missing HSTS" finding.
 *
 * It is asked of hstspreload.org's status API for the EXACT host. The API answers "preloaded" for a host that
 * is on the list itself or sits under a listed parent that includes its subdomains (docs.github.com is covered by
 * github.com), and the answer for a host under a parent that does NOT include subdomains is "unknown", which
 * stripping "www." and asking about the apex got wrong.
 *
 * Only "preloaded" counts; "pending" (submitted, not yet shipped), "rejected" and "unknown" do not. Any failure
 * to get an answer also means "not preloaded", so the finding is still raised: a preloaded host sends the
 * header anyway, because the list only accepts hosts that do.
 *
 * Two things this used to do and no longer does, both found by repeating a 50-site sweep (2026-10-10) in which
 * no site got a "Missing HSTS" finding although six verifiably send no such header and are not listed:
 *
 *  1. Suppress the finding when `http://<host>/` redirects to HTTPS. A redirect is the thing HSTS exists to
 *     back up: the first visit still goes over plain HTTP, where it can be stripped. Almost every site
 *     redirects, so this suppressed almost every finding.
 *  2. Suppress it for a hardcoded set of 40 names "built into Chrome". Checked against Chromium's list
 *     (net/http/transport_security_state_static.json, 95,147 entries, fetched 2026-10-11), 23 of those 40 are
 *     not on it: google.com, apple.com, microsoft.com, linkedin.com, x.com, shopify.com, box.com, outlook.com,
 *     office.com, live.com, appspot.com, github.io and others (amazon.com is not listed, only www.amazon.com).
 *     The API already says "preloaded" for the 17 that are, so the set only added wrong answers. Google's
 *     own subdomains that are listed, such as mail.google.com and accounts.google.com, come back from the
 *     API as "preloaded" when asked about directly.
 */
export async function isHstsPreloaded(hostname: string): Promise<boolean> {
  const host = hostname.trim().toLowerCase().replace(/\.$/, "");
  if (!host || isIP(host) || !host.includes(".") || NEVER_PRELOADED.test(host)) return false;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5_000);
  try {
    const res = await fetch(`${hstsPreloadApiUrl()}?domain=${encodeURIComponent(host)}`, { signal: ctrl.signal });
    if (!res.ok) return false;
    const json = (await res.json()) as { status?: string };
    return json.status === "preloaded";
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
