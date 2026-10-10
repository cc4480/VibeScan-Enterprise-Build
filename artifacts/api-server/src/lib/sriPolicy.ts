/**
 * Which external scripts and stylesheets should be expected to carry Subresource
 * Integrity, and which should not.
 *
 * The check used to flag every resource whose hostname differed from the page's. On
 * real sites that is wrong twice over:
 *
 *  1. FIRST-PARTY CDNs. static.example.com and cdn.example.com on www.example.com
 *     are the site's own, under its own DNS. SRI protects against a compromised
 *     third party, not against the site's own subdomain.
 *
 *  2. SCRIPTS THAT MUST NOT HAVE SRI. Google Tag Manager, Stripe.js, reCAPTCHA and the
 *     like are updated in place by the provider under the same URL. An integrity hash
 *     pins one version; the next update fails the hash and the script (a payment form,
 *     a captcha) silently stops working. Stripe's own documentation says not to add
 *     SRI. Reporting these tells people to break their site.
 *
 * Both errors are in the direction of a false alarm, so both are corrected. The
 * opposite risk, a genuine third party treated as first-party, only costs a Medium
 * note, and the rule below keeps that rare.
 */

/**
 * Two-part public suffixes. Without the public-suffix list (thousands of entries) the
 * rule must not treat a.co.uk and b.co.uk as one organisation, so these are known.
 * Others fall through to "share two labels", which errs toward first-party: a missed
 * note, never a false one.
 */
const TWO_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "govt.nz",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "co.kr", "or.kr", "co.in", "net.in", "org.in", "firm.in",
  "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co", "com.pe", "com.cl",
  "co.za", "org.za", "com.cn", "net.cn", "org.cn", "com.hk", "com.sg", "com.tw", "com.my", "com.ph", "com.vn",
  "com.tr", "com.ua", "com.pl", "co.il", "co.id", "co.th", "com.eg", "com.ng", "com.sa", "co.ke",
]);

const labelsOf = (host: string) => host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);

/** The number of trailing labels two hostnames share. */
function sharedSuffixLabels(a: string[], b: string[]): number {
  let n = 0;
  while (n < a.length && n < b.length && a[a.length - 1 - n] === b[b.length - 1 - n]) n += 1;
  return n;
}

/**
 * Is `resourceHost` part of the same site as `pageHost`?
 * Same host, or a subdomain of it, or a sibling under the same registrable domain
 * (www.example.com and static.example.com). Never across a public suffix.
 */
/** A site's own CDN under a different registrable domain: [site, its CDN]. */
const OWNED_CDNS: Array<[string, string]> = [
  ["dropbox.com", "dropboxstatic.com"], ["stripe.com", "stripecdn.com"], ["linkedin.com", "licdn.com"],
  ["theguardian.com", "guim.co.uk"],
  // HubSpot serves its app assets and consent banner from domains it owns.
  ["hubspot.com", "hsappstatic.net"], ["hubspot.com", "hs-banner.com"],
];

export function isFirstParty(pageHost: string, resourceHost: string): boolean {
  const ph = pageHost.toLowerCase(), rh = resourceHost.toLowerCase();
  const under = (h: string, d: string) => h === d || h.endsWith("." + d);
  if (OWNED_CDNS.some(([site, cdn]) => under(ph, site) && under(rh, cdn))) return true;
  const a = labelsOf(pageHost);
  const b = labelsOf(resourceHost);
  if (a.length === 0 || b.length === 0) return false;
  const shared = sharedSuffixLabels(a, b);
  const suffix = a.slice(a.length - shared).join(".");
  // A shared suffix that is itself a public suffix (co.uk) makes them strangers.
  if (shared === 0 || TWO_PART_SUFFIXES.has(suffix)) return false;
  // Not enough labels to be a registrable domain (just "com"): strangers.
  return shared >= 2;
}

/** Hosts whose scripts are updated in place, so an integrity hash would break them. */
const DYNAMIC_HOSTS = new Set([
  "www.googletagmanager.com", "googletagmanager.com", "www.google-analytics.com", "ssl.google-analytics.com", "analytics.google.com",
  "js.stripe.com", "m.stripe.network", "checkout.stripe.com", "js.stripe.network",
  "www.recaptcha.net", "recaptcha.net", "js.hcaptcha.com", "hcaptcha.com", "challenges.cloudflare.com",
  "fonts.googleapis.com", "apis.google.com", "accounts.google.com", "maps.googleapis.com",
  "connect.facebook.net", "platform.twitter.com", "platform.linkedin.com", "snap.licdn.com",
  "static.cloudflareinsights.com", "js.hs-scripts.com", "js.hsforms.net", "js.usemessages.com",
  "widget.intercom.io", "js.intercomcdn.com", "static.hotjar.com", "script.hotjar.com", "cdn.heapanalytics.com",
  "www.paypal.com", "www.paypalobjects.com", "js.sentry-cdn.com",
  // Consent managers and bot protection: configured and updated by the provider, so they cannot be pinned.
  "cdn.cookielaw.org", "geolocation.onetrust.com", "cdn.cookiepro.com", "consent.cookiebot.com", "consentcdn.cookiebot.com",
  "cdn.transcend.io", "transcend-cdn.com", "cmp.osano.com", "cdn.iubenda.com", "app.termly.io", "cdn.cookieyes.com",
  "ct.captcha-delivery.com", "js.datadome.co", "rum.hlx.page",
]);

/** Path-scoped: the same host serves both stable and provider-updated files. */
const DYNAMIC_PATHS: Array<{ host: string; prefix: string }> = [
  { host: "www.google.com", prefix: "/recaptcha/" },
  { host: "www.gstatic.com", prefix: "/recaptcha/" },
  { host: "www.gstatic.com", prefix: "/firebasejs/" },
];

/** Per-customer subdomains of a provider that cannot be pinned (AWS WAF serves challenge.js from <id>.edge.sdk.awswaf.com). */
const DYNAMIC_SUFFIXES = ["sdk.awswaf.com"];

export function isDynamicByDesign(resource: URL): boolean {
  const host = resource.hostname.toLowerCase();
  if (DYNAMIC_HOSTS.has(host)) return true;
  if (DYNAMIC_SUFFIXES.some((s) => host.endsWith("." + s))) return true;
  return DYNAMIC_PATHS.some((p) => p.host === host && resource.pathname.startsWith(p.prefix));
}

/**
 * Should a resource without an integrity attribute be reported?
 *
 * `alsoFirstParty` lists other hosts the site answers to: the address the user asked to scan, when it
 * redirected somewhere else. zoom.us redirects to www.zoom.com but keeps its assets on st1.zoom.us;
 * judged against the final host alone, Zoom's own CDN read as a stranger.
 */
export function expectsIntegrity(pageHost: string, resource: URL, alsoFirstParty: string[] = []): boolean {
  const own = [pageHost, ...alsoFirstParty].some((h) => isFirstParty(h, resource.hostname));
  return !own && !isDynamicByDesign(resource);
}

/**
 * Marketing and analytics tags that the provider edits in place under a fixed URL. The finding is still
 * true for them (a compromised vendor runs code on the page), but "add an integrity attribute" is advice
 * that breaks them: the next vendor update fails the hash and the tag silently stops. They are reported
 * with advice that can be followed. Matched on the host or any parent domain.
 */
const VENDOR_UPDATED_DOMAINS = [
  "bizible.com", "marketo.net", "marketo.com", "mktoresp.com", "munchkin.marketo.net",
  "parsely.com", "clearbit.com", "clearbitjs.com", "digitalgov.gov",
  "segment.com", "segment.io", "fullstory.com", "mouseflow.com", "drift.com", "driftt.com",
  "pardot.com", "pi.pardot.com", "demandbase.com", "6sc.co", "6sense.com", "zoominfo.com",
  "optimizely.com", "usefathom.com", "mixpanel.com", "amplitude.com", "quantserve.com", "taboola.com", "outbrain.com",
];

export function isVendorUpdated(resource: URL): boolean {
  const h = resource.hostname.toLowerCase();
  return VENDOR_UPDATED_DOMAINS.some((d) => h === d || h.endsWith("." + d));
}
