/**
 * Detection for pages a hosting platform or an identity provider serves in place of the app.
 *
 * challengePage.ts covers bot-protection interstitials. This covers the other ways a scan reaches
 * something that is not the customer's app at all, and then grades it as if it were:
 *
 *  - a sign-in wall in front of the whole site: Vercel Deployment Protection, Cloudflare Access, or
 *    a redirect to an identity provider (Google, Microsoft, Auth0, Clerk, Okta, Replit, GitHub);
 *  - the platform's own "nothing is running here" page: a Vercel deployment that is not found or
 *    paused, Railway's fallback, a Render service with no server, a Heroku error page.
 *
 * Every such page looks the same whichever app sits behind it, so every app behind one gets the
 * same report: the platform's headers, the platform's cookies, the platform's missing Open Graph
 * tags. That is the "every scan comes back the same" failure, and none of it is true of the app.
 *
 * Same rule as challengePage.ts: a match needs a vendor-specific signal (a response header the
 * platform sets, a host only it uses, a path only its page loads), never a phrase that could be
 * ordinary page copy. A false match would hide real findings.
 *
 * The signals below were taken from the platforms' documentation and public error pages, not
 * captured from live responses in this environment (it has no outbound access); each has a test.
 */

export type GateKind = "sign-in wall" | "app not running";

export interface GateVerdict {
  isGate: boolean;
  kind: GateKind | null;
  vendor: string | null;
  /** What matched, for evidence. */
  signal: string | null;
}

const NOT_A_GATE: GateVerdict = { isGate: false, kind: null, vendor: null, signal: null };

function host(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function pathAndQuery(url: string): string {
  try {
    const u = new URL(url);
    return `${u.pathname}${u.search}`;
  } catch {
    return "";
  }
}

/**
 * Identity-provider sign-in pages, recognised by where the scan landed. Host plus path where the
 * host also serves ordinary content (github.com, replit.com, vercel.com).
 */
const SIGN_IN_DESTINATIONS: { vendor: string; host: RegExp; path?: RegExp }[] = [
  { vendor: "Cloudflare Access", host: /\.cloudflareaccess\.com$/ },
  { vendor: "Google sign-in", host: /^accounts\.google\.com$/ },
  { vendor: "Microsoft sign-in", host: /^login\.(?:microsoftonline|live)\.com$/ },
  { vendor: "Auth0", host: /\.auth0\.com$/ },
  { vendor: "Clerk", host: /^accounts\.[^.]+\.[^.]+$|\.accounts\.dev$/, path: /^\/sign-?in\b/i },
  { vendor: "Okta", host: /\.okta(?:preview)?\.com$/ },
  { vendor: "OneLogin", host: /\.onelogin\.com$/ },
  { vendor: "GitHub sign-in", host: /^github\.com$/, path: /^\/login\b/i },
  { vendor: "Replit sign-in", host: /^replit\.com$/, path: /^\/(?:login|auth_with_repl_site|signup)\b/i },
  { vendor: "Vercel Deployment Protection", host: /^vercel\.com$/, path: /^\/(?:login|sso-api)\b/i },
  { vendor: "Netlify sign-in", host: /^app\.netlify\.com$/ },
];

/**
 * Platform responses identified by a response header whose VALUE says the platform answered.
 * Header names alone prove nothing: x-vercel-id is on every Vercel response.
 */
const HEADER_SIGNALS: { vendor: string; kind: GateKind; header: string; re: RegExp }[] = [
  { vendor: "Vercel", kind: "app not running", header: "x-vercel-error", re: /^DEPLOYMENT_(?:NOT_FOUND|DISABLED|PAUSED|BLOCKED|DELETED)$|^NO_RESPONSE_FROM_FUNCTION$/i },
  { vendor: "Railway", kind: "app not running", header: "x-railway-fallback", re: /^true$/i },
  { vendor: "Render", kind: "app not running", header: "x-render-routing", re: /no-?server|no-?deploy|suspend/i },
];

/** Platform pages recognised by markup only that platform's page carries. Error statuses only. */
const BODY_SIGNALS: { vendor: string; kind: GateKind; re: RegExp; label: string }[] = [
  { vendor: "Vercel Deployment Protection", kind: "sign-in wall", re: /vercel\.com\/sso-api|_vercel_sso_nonce/i, label: "Vercel SSO redirect in the page" },
  { vendor: "Cloudflare Access", kind: "sign-in wall", re: /\/cdn-cgi\/access\/login/i, label: "Cloudflare Access login path in the page" },
  { vendor: "Heroku", kind: "app not running", re: /herokucdn\.com\/error-pages\/(?:application-error|no-such-app)/i, label: "Heroku error page" },
  { vendor: "GitHub Pages", kind: "app not running", re: /There isn't a GitHub Pages site here/i, label: "GitHub Pages not-found page" },
];

/**
 * Decide whether the document the scan is about to analyse is a platform's or identity provider's
 * page rather than the app at the address the user typed.
 *
 * `headers` keys are expected lowercased, as the scanner normalises them.
 */
export function detectPlatformGate(
  requestedUrl: string,
  finalUrl: string,
  status: number,
  html: string,
  headers: Record<string, string> = {},
): GateVerdict {
  const requestedHost = host(requestedUrl);
  const finalHost = host(finalUrl);

  // Where the scan landed. Only when it left the requested host: the identity provider's own
  // domain scanned on purpose is not a gate.
  if (finalHost && finalHost !== requestedHost) {
    const path = pathAndQuery(finalUrl);
    for (const d of SIGN_IN_DESTINATIONS) {
      if (d.host.test(finalHost) && (!d.path || d.path.test(path))) {
        return {
          isGate: true,
          kind: "sign-in wall",
          vendor: d.vendor,
          signal: `${requestedUrl} redirected to ${finalUrl.slice(0, 160)}`,
        };
      }
    }
  }

  for (const h of HEADER_SIGNALS) {
    const value = headers[h.header];
    if (value !== undefined && h.re.test(value.trim())) {
      return { isGate: true, kind: h.kind, vendor: h.vendor, signal: `${h.header}: ${value.slice(0, 60)} (HTTP ${status})` };
    }
  }

  // Body markers count only on an error status and a page-sized document: a working page can
  // link to a sign-in path, and a 401 or 404 from the platform is short.
  if (status >= 400 && html.length < 60_000) {
    for (const b of BODY_SIGNALS) {
      if (b.re.test(html)) return { isGate: true, kind: b.kind, vendor: b.vendor, signal: `${b.label} (HTTP ${status})` };
    }
  }

  return NOT_A_GATE;
}

/**
 * Where the scan ended up, when that is not the site the user asked for and not a recognised gate.
 * Returned so the report can say "these findings describe X", never used to withhold anything:
 * a brand that redirects to its other domain is still the brand's site.
 */
export function landedElsewhere(requestedUrl: string, finalUrl: string): string | null {
  const a = host(requestedUrl).replace(/^www\./, "");
  const b = host(finalUrl).replace(/^www\./, "");
  if (!a || !b || a === b) return null;
  if (b.endsWith(`.${a}`) || a.endsWith(`.${b}`)) return null;
  return b;
}
