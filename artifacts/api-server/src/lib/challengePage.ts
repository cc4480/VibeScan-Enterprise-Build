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
const BODY_SIGNALS: { vendor: string; re?: RegExp; all?: RegExp[]; label: string }[] = [
  // The INTERSTITIAL's script lives under .../orchestrate/ (chl_page, jsch, managed). The bare
  // /cdn-cgi/challenge-platform/ prefix is not enough: Cloudflare injects
  // <script>a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'</script> into ordinary pages
  // it proxies, for passive bot detection, and matching the prefix read secscan.us's own 23 KB
  // homepage as a challenge and withheld every header, cookie and CSP finding for it.
  { vendor: "Cloudflare", re: /\/cdn-cgi\/challenge-platform\/(?:h\/[a-z]\/)?orchestrate\//i, label: "/cdn-cgi/challenge-platform/ orchestrate script" },
  // No word boundary before cf_chl_opt: the markup Cloudflare actually emits is
  // `window._cf_chl_opt={...}`, and "_" is a word character, so a leading 
  // never matched the real-world form. Found while porting this file to
  // seclayer.io2026, where a test of the live markup failed.
  { vendor: "Cloudflare", re: /cf_chl_opt|__cf_chl_/i, label: "cf_chl_opt challenge payload" },
  { vendor: "Cloudflare", re: /cf-browser-verification|cf-im-under-attack/i, label: "cf-browser-verification marker" },
  { vendor: "Cloudflare", re: /<title>\s*Attention Required!\s*\|\s*Cloudflare\s*<\/title>/i, label: "Cloudflare block title" },
  { vendor: "Imperva/Incapsula", re: /Incapsula incident ID/i, label: "Incapsula block-page incident ID" },
  { vendor: "Akamai", re: /errors\.edgesuite\.net|AkamaiGHost/i, label: "Akamai error host" },
  // Akamai Bot Manager's interstitial: a ~2 KB page that posts a proof-of-work
  // to /_sec/verify and reloads. Found on amazon.co.uk (2026-09-24), where it was
  // scored as Amazon's homepage — five findings, one HIGH, about a page Amazon
  // never published. Each token is specific to the challenge script; none appears
  // in ordinary page content.
  { vendor: "Akamai Bot Manager", re: /\/_sec\/verify\?provider=interstitial|triggerInterstitialChallenge|[?&'"]bm-verify=/i, label: "Akamai bot-manager interstitial" },
  // Amazon's own "Continue shopping" robot check, served to non-browser clients.
  // The form target is a path only that page posts to.
  { vendor: "Amazon", re: /\/errors(?:_page)?\/validateCaptcha/i, label: "Amazon robot-check form" },
  // wafw00f's Sucuri plugin (checked 2026-10-02) keys on the block page's title and stylesheet, not on
  // the product name, which a security blog or a Sucuri customer's own page also carries.
  { vendor: "Sucuri", re: /<title>\s*Sucuri WebSite Firewall[^<]{0,30}Access Denied|cdn\.sucuri\.net\/sucuri[-_]firewall[-_]block\.css|Access Denied[^<]{0,12}Sucuri Website Firewall|sucuri_cloudproxy/i, label: "Sucuri firewall page" },
  // The vendors' challenge surfaces only. Their sensor tags (js.datadome.co, client.perimeterx.net,
  // /_Incapsula_Resource, *.awswaf.com/challenge.js) are on ordinary pages of every customer, so
  // they count only on a bare stub document; see SENSOR_SIGNALS.
  { vendor: "PerimeterX", re: /px-captcha|perimeterx\.(?:com|net)\/whywasiblocked|denied because we believe you are using automation tools/i, label: "PerimeterX challenge" },
  // Vercel's checkpoint page also loads from /vercel/security/ (wafw00f, checked 2026-10-02).
  { vendor: "Vercel", re: /\/vercel\/security\//i, label: "Vercel security checkpoint script" },
  { vendor: "DataDome", re: /geo\.captcha-delivery\.com/i, label: "DataDome challenge" },
  // Reddit's proof-of-work interstitial (server: snooserv): a ~8 KB page titled just "Reddit"
  // whose only content is a hidden GET form that a script fills in and submits. Its title and
  // headers carry no signal, and it ships its own CSP, which the crawler then took for the
  // site's baseline (2026-09-29: "Content-Security-Policy Missing on 6 Internal Routes"). The
  // form's two challenge inputs are what identify it, and BOTH are required: either name alone
  // could be an ordinary form field or a sentence in a developer's write-up.
  { vendor: "Reddit", all: [/name=["']js_challenge["']/i, /name=["']jsc_token["']/i], label: "Reddit js_challenge form" },
];

/**
 * Vendor sensor/loader references. A customer's real page loads these too
 * (DataDome's tags.js, PerimeterX's sensor, Imperva's injected /_Incapsula_Resource, the AWS WAF
 * SDK), so the reference alone proves nothing. The vendor's actual JS challenge is a stub whose
 * only job is to load that script, so a match counts only in markup (never prose) of a stub
 * document (isStubDocument). Same class as the /cdn-cgi/challenge-platform/ bug above.
 */
const SENSOR_SIGNALS: { vendor: string; re: RegExp; label: string }[] = [
  { vendor: "Imperva/Incapsula", re: /_Incapsula_Resource/i, label: "Incapsula challenge stub" },
  { vendor: "PerimeterX", re: /perimeterx|_pxhd/i, label: "PerimeterX challenge stub" },
  { vendor: "DataDome", re: /datadome/i, label: "DataDome challenge stub" },
  { vendor: "AWS WAF", re: /awswaf\.com|aws-waf-token|AwsWafIntegration/i, label: "AWS WAF challenge stub" },
];

/** Text between tags dropped (script bodies kept, they are code), so a mention in prose is not a reference. */
function markupOnly(html: string): string {
  return html.replace(/(<script\b[\s\S]*?<\/script>)|>[^<]*</gi, (_m, script?: string) => script ?? "><");
}

/**
 * A challenge stub has no page in it: a few KB, almost no visible text and none of the
 * structure a published page has (headings, paragraphs, navigation, footer).
 */
function isStubDocument(html: string): boolean {
  if (html.length > 6_000) return false;
  // A <noscript> block is where a challenge explains itself to a client that cannot run its script
  // ("JavaScript is disabled ... verify that you're not a robot"), usually under a heading.
  // booking.com's AWS WAF stub (2026-10-05) has an <h1> there; it read as page structure and a 4 KB
  // interstitial was graded as booking.com's homepage. A visitor who runs scripts never sees that
  // block, so it counts for neither structure nor visible text.
  const body = html.replace(/<noscript\b[\s\S]*?<\/noscript>/gi, "");
  if (/<(?:h[1-6]|p|nav|footer|main|article|section)\b/i.test(body)) return false;
  const visible = body.replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
  return visible.length < 150;
}

/**
 * Interstitial titles.
 *
 * Matched against the <title> only, and anchored, because "Just a moment" in
 * body copy is ordinary English while a document whose entire title is "Just a
 * moment..." is not a page anyone published.
 */
const TITLE_SIGNALS: { vendor: string; re: RegExp; anySize?: true }[] = [
  { vendor: "Cloudflare", re: /^just a moment\.{0,3}$/i },
  { vendor: "Cloudflare", re: /^attention required!/i },
  { vendor: "Cloudflare", re: /^access denied \| .*cloudflare/i },
  { vendor: "Vercel", re: /^vercel security checkpoint$/i },
  { vendor: "generic WAF", re: /^(checking your browser|please wait\.{0,3}|one more step|security check)$/i },
  { vendor: "generic WAF", re: /^(403 forbidden|access denied|request blocked|blocked)$/i },
  // Akamai's block page as microsoft.com's edge serves it (2026-09-29): HTTP 200, 201 KB, the
  // site's full header and footer wrapped around this title, no errors.edgesuite.net and no
  // AkamaiGHost token anywhere in it. The whole <title> is one fixed sentence no site publishes
  // as a page title, so it is trusted at any size; a 200 KB block page defeats the ceiling below.
  { vendor: "Akamai", re: /^your request has been blocked\. this could be due to several reasons\.?$/i, anySize: true },
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
  // Vercel's Attack Challenge Mode / Firewall challenge ("Vercel Security Checkpoint").
  { vendor: "Vercel", header: "x-vercel-mitigated", re: /challenge|deny|block/i, label: "x-vercel-mitigated response header" },
];

/**
 * The statuses an edge or a firewall answers with when it turns a request away: forbidden, too many
 * requests, unavailable, unavailable for legal reasons, and the two that a request's own shape provokes,
 * bad request and not acceptable. 406 was missing. www.elastic.co (Fastly) answered the scanner's
 * request with HTTP 406 and the 20-byte body "406 Not Acceptable", and the scan went on to report that
 * response's missing Content-Security-Policy (HIGH), missing X-Frame-Options, missing cache headers,
 * no structured data and no Open Graph tags: five claims that are false of the real page (2026-10-10;
 * reproduced 2026-10-11 with curl by sending the scanner's Cache-Control and Pragma headers, which is
 * what provokes it). 404 and the 5xx statuses are not here: they say the page or the server is
 * missing, not that the request was refused.
 */
const REFUSAL_STATUSES = new Set([400, 403, 406, 429, 451, 503]);

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
  if (title) {
    for (const t of TITLE_SIGNALS) {
      if (!looksInterstitial && !t.anySize) continue;
      if (t.re.test(title)) {
        return { isChallenge: true, vendor: t.vendor, signal: `interstitial title: "${title.slice(0, 80)}"` };
      }
    }
  }

  if (looksInterstitial) {
    for (const b of BODY_SIGNALS) {
      const hit = b.all ? b.all.every((re) => re.test(html)) : (b.re?.test(html) ?? false);
      if (hit) return { isChallenge: true, vendor: b.vendor, signal: b.label };
    }
    if (isStubDocument(html)) {
      const markup = markupOnly(html);
      for (const b of SENSOR_SIGNALS) {
        if (b.re.test(markup)) return { isChallenge: true, vendor: b.vendor, signal: b.label };
      }
    }
  }

  // A bare refusal with almost no body is an interception even when no vendor
  // signed it. Anything with real content is left alone: an empty-ish error
  // page is not something a site publishes as its homepage.
  if (REFUSAL_STATUSES.has(status) && html.replace(/\s+/g, "").length < 2_000) {
    return { isChallenge: true, vendor: null, signal: `HTTP ${status} with a ${html.length}-byte body` };
  }

  return NOT_A_CHALLENGE;
}
