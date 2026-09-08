/**
 * Detection for WAF challenge and block pages.
 *
 * When a target's edge decides the scanner is a bot, it does not fail the
 * request — it returns 200, 403 or 503 with a complete HTML document of its
 * own. Everything downstream then analyses that document: the CSP belongs to
 * Cloudflare, the cookies are the challenge's, the missing Open Graph tags are
 * missing from an interstitial nobody publishes. The report describes the WAF
 * and is attributed to the customer's site.
 *
 * This was found while testing structured-data checks against real sites.
 * stackoverflow.com and npmjs.com both returned 403 "Just a moment..." pages
 * carrying `noindex,nofollow`, and the scanner faithfully reported that their
 * homepages were excluded from search indexes. The same interception silently
 * distorts every other content-derived check.
 *
 * Detection is deliberately strict. Calling a real page a challenge page would
 * suppress genuine findings, which is a worse failure than the one being fixed,
 * so a match needs an unambiguous vendor fingerprint — a challenge-platform
 * script path, a vendor header, a known interstitial title — and never a
 * phrase that could appear in ordinary prose.
 */

export interface ChallengeVerdict {
  /** True only when a vendor fingerprint matched. */
  isChallenge: boolean;
  vendor: string | null;
  /** What matched, for evidence. */
  signal: string | null;
}

const NOT_A_CHALLENGE: ChallengeVerdict = { isChallenge: false, vendor: null, signal: null };

/**
 * Body fingerprints. Each is a vendor-specific asset path, script token or
 * verbatim interstitial string — never a phrase a normal page might contain.
 */
const BODY_SIGNALS: { vendor: string; re: RegExp; label: string }[] = [
  { vendor: "Cloudflare", re: /\/cdn-cgi\/challenge-platform\//i, label: "/cdn-cgi/challenge-platform/ script" },
  { vendor: "Cloudflare", re: /\bcf_chl_opt\b|\b__cf_chl_/i, label: "cf_chl_opt challenge payload" },
  { vendor: "Cloudflare", re: /cf-browser-verification|cf-im-under-attack/i, label: "cf-browser-verification marker" },
  { vendor: "Cloudflare", re: /<title>\s*Attention Required!\s*\|\s*Cloudflare\s*<\/title>/i, label: "Cloudflare block title" },
  { vendor: "Imperva/Incapsula", re: /_Incapsula_Resource|Incapsula incident ID/i, label: "Incapsula resource marker" },
  { vendor: "Akamai", re: /errors\.edgesuite\.net|AkamaiGHost/i, label: "Akamai error host" },
  { vendor: "Sucuri", re: /Sucuri WebSite Firewall|sucuri_cloudproxy/i, label: "Sucuri firewall page" },
  { vendor: "PerimeterX", re: /_pxhd|px-captcha|perimeterx/i, label: "PerimeterX challenge" },
  { vendor: "DataDome", re: /datadome|geo\.captcha-delivery\.com/i, label: "DataDome challenge" },
  { vendor: "AWS WAF", re: /awswaf\.com|aws-waf-token/i, label: "AWS WAF token" },
];

/**
 * Interstitial titles.
 *
 * Matched against the <title> only, and anchored, because "Just a moment" in
 * body copy is ordinary English while a document whose entire title is "Just a
 * moment..." is not a page anyone published.
 */
const TITLE_SIGNALS: { vendor: string; re: RegExp }[] = [
  { vendor: "Cloudflare", re: /^just a moment\.{0,3}$/i },
  { vendor: "Cloudflare", re: /^attention required!/i },
  { vendor: "Cloudflare", re: /^access denied \| .*cloudflare/i },
  { vendor: "generic WAF", re: /^(checking your browser|please wait\.{0,3}|one more step|security check)$/i },
  { vendor: "generic WAF", re: /^(403 forbidden|access denied|request blocked|blocked)$/i },
];

/**
 * Response headers that identify an interception.
 *
 * The VALUE decides, never the presence — `re` is required for exactly that
 * reason. These headers are set on allowed traffic too: nytimes.com serves its
 * real homepage, 1.3MB with two JSON-LD blocks, under `x-datadome: protected`,
 * which means the request passed. Treating the header as a verdict marked the
 * New York Times as blocked while its content sat in the response body.
 */
const HEADER_SIGNALS: { vendor: string; header: string; re: RegExp; label: string }[] = [
  { vendor: "Cloudflare", header: "cf-mitigated", re: /challenge|block/i, label: "cf-mitigated response header" },
  { vendor: "DataDome", header: "x-datadome", re: /block|challenge|captcha/i, label: "x-datadome response header" },
  { vendor: "AWS WAF", header: "x-amzn-waf-action", re: /block|challenge|captcha/i, label: "x-amzn-waf-action response header" },
];

function titleOf(html: string): string | null {
  const m = /<title\b[^>]*>([\s\S]{0,200}?)<\/title\s*>/i.exec(html);
  return m ? (m[1] ?? "").replace(/\s+/g, " ").trim() : null;
}

/**
 * Decide whether a response is an edge challenge rather than the target's page.
 *
 * `headers` keys are expected lowercased, as the scanner already normalises
 * them.
 */
export function detectChallengePage(
  status: number,
  html: string,
  headers: Record<string, string> = {},
): ChallengeVerdict {
  for (const h of HEADER_SIGNALS) {
    const value = headers[h.header];
    if (value !== undefined && h.re.test(value)) {
      return { isChallenge: true, vendor: h.vendor, signal: `${h.label}: ${value.slice(0, 60)}` };
    }
  }

  // Body fingerprints are vendor-specific enough to stand on their own, but a
  // large document is a real page that merely loads a vendor's script, so the
  // interstitial size ceiling still applies.
  const looksInterstitial = html.length < 60_000;

  const title = titleOf(html);
  if (title && looksInterstitial) {
    for (const t of TITLE_SIGNALS) {
      if (t.re.test(title)) {
        return { isChallenge: true, vendor: t.vendor, signal: `interstitial title: "${title.slice(0, 80)}"` };
      }
    }
  }

  if (looksInterstitial) {
    for (const b of BODY_SIGNALS) {
      if (b.re.test(html)) {
        return { isChallenge: true, vendor: b.vendor, signal: b.label };
      }
    }
  }

  // A bare 403/503 with almost no body is an interception even when no vendor
  // signed it. Anything with real content is left alone: an empty-ish error
  // page is not something a site publishes as its homepage.
  if ((status === 403 || status === 503 || status === 429) && html.replace(/\s+/g, "").length < 2_000) {
    return { isChallenge: true, vendor: null, signal: `HTTP ${status} with a ${html.length}-byte body` };
  }

  return NOT_A_CHALLENGE;
}
