/**
 * Technology fingerprint detection.
 * Inspects HTTP response headers and HTML to identify the frameworks,
 * CDNs, and platforms the target site uses.
 *
 * Extracted from scanner.ts to keep the main scanner file focused on
 * orchestration and vulnerability analysis.
 */

import { assetUrls, scriptText, generators, loadsFromHost } from "./techEvidence.js";

function headerVal(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  const key = Object.keys(headers).find((k) => k.toLowerCase() === lower);
  return key ? headers[key] : undefined;
}

/**
 * Tailwind utilities carry a scale suffix — `px-4`, `text-sm`, `bg-white`,
 * `rounded-lg`, `gap-6` — and that suffix is what separates them from the
 * ordinary layout words a hand-written stylesheet uses. `grid` and `flex` alone
 * mean nothing; `grid-cols-3` and `gap-4` together mean Tailwind.
 *
 * Counting DISTINCT utilities rather than testing for one matters: a bespoke
 * stylesheet can easily own a single `text-sm`, but owning five unrelated
 * utilities in Tailwind's exact shape, by coincidence, does not happen.
 */
const TAILWIND_UTILITY =
  /(?<![\w-])(?:p[xytrbl]?|m[xytrbl]?|gap(?:-[xy])?|space-[xy]|text|bg|border|rounded|shadow|w|h|min-[wh]|max-[wh]|grid-cols|col-span|row-span|leading|tracking|z|opacity|ring|inset|font|items|justify|self|order|basis|flex)-(?:\[[^\]\s"']+\]|[0-9]+(?:\.[0-9]+)?|[0-9]+\/[0-9]+|px|auto|full|screen|fit|min|max|none|dvh|dvw|svh|lvh|xs|sm|base|md|lg|xl|[2-9]xl|black|white|transparent|current|inherit|(?:slate|gray|grey|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)(?:-[0-9]{2,3})?)(?![\w-])/g;

/** Five distinct utilities is the threshold; see TAILWIND_UTILITY. */
const TAILWIND_MIN_UTILITIES = 5;

function countTailwindUtilities(html: string): number {
  const seen = new Set<string>();
  for (const m of html.matchAll(TAILWIND_UTILITY)) {
    seen.add(m[0].toLowerCase());
    if (seen.size >= TAILWIND_MIN_UTILITIES) return seen.size;
  }
  return seen.size;
}

export function detectTechnologies(headers: Record<string, string>, html: string): string[] {
  const techs = new Set<string>();

  // ── Server header ────────────────────────────────────────────────────
  const server = headerVal(headers, "server") ?? "";
  if (/nginx/i.test(server))                      techs.add("Nginx");
  // Apache-Coyote is Tomcat's connector banner, not the Apache httpd.
  if (/apache(?!-coyote)/i.test(server))          techs.add("Apache");
  if (/microsoft-iis/i.test(server))              techs.add("IIS");
  if (/cloudflare/i.test(server))                 techs.add("Cloudflare");
  if (/vercel/i.test(server))                     techs.add("Vercel");
  if (/fastly/i.test(server))                     techs.add("Fastly");
  if (/litespeed/i.test(server))                  techs.add("LiteSpeed");
  if (/openresty/i.test(server))                  techs.add("OpenResty");
  if (/caddy/i.test(server))                      techs.add("Caddy");
  if (/gunicorn/i.test(server))                   techs.add("Gunicorn");
  // \b: "gunicorn" contains "unicorn" but is not the Unicorn server.
  if (/\bunicorn\b/i.test(server))                techs.add("Unicorn");
  if (/\b(?:cpython|python|werkzeug|wsgiserver|uvicorn|hypercorn)\b/i.test(server)) techs.add("Python");
  if (/cowboy/i.test(server))                     techs.add("Cowboy");
  if (/kestrel/i.test(server))                    techs.add("Kestrel (.NET)");
  if (/gfe|google frontend/i.test(server))        techs.add("Google Cloud / GFE");
  if (/aws|amazon/i.test(server))                 techs.add("AWS");
  if (/envoy/i.test(server))                      techs.add("Envoy Proxy");
  if (/netlify/i.test(server))                    techs.add("Netlify");
  if (/^railway$/i.test(server.trim()))           techs.add("Railway");
  if (/squarespace/i.test(server))                techs.add("Squarespace");
  // Word-bounded: "AkamaiGHost" is Akamai's edge server and contains "ghost", so
  // every Akamai-fronted site (amazon.co.uk among them) was listed as running the
  // Ghost blogging platform, and the CVE monitor matches technology names.
  if (/\bghost\b/i.test(server))                  techs.add("Ghost");
  if (/webflow/i.test(server))                    techs.add("Webflow");

  // ── CDN / infrastructure headers ─────────────────────────────────────
  if (headerVal(headers, "cf-ray"))               techs.add("Cloudflare");
  if (headerVal(headers, "cf-cache-status"))      techs.add("Cloudflare");
  if (headerVal(headers, "x-vercel-id"))          techs.add("Vercel");
  if (headerVal(headers, "x-netlify") || headerVal(headers, "x-nf-request-id")) techs.add("Netlify");
  if (headerVal(headers, "replit-cluster"))       techs.add("Replit");
  // x-amz-cf-id is CloudFront's; x-amz-request-id is sent by S3 and other AWS APIs (webappanalyzer
  // files it under Amazon Web Services, checked 2026-10-02), so it must not name CloudFront.
  if (headerVal(headers, "x-amz-cf-id"))           techs.add("AWS CloudFront");
  else if (headerVal(headers, "x-amz-request-id")) techs.add("AWS");
  if (headerVal(headers, "x-azure-ref"))          techs.add("Azure");
  if (headerVal(headers, "x-ms-request-id"))      techs.add("Azure");
  // x-github-request-id is sent by github.com and api.github.com too, so on its own it
  // tagged GitHub's own site as a Pages site. Pages also adds x-proxy-cache.
  if (headerVal(headers, "x-github-request-id") && headerVal(headers, "x-proxy-cache")) techs.add("GitHub Pages");
  if (headerVal(headers, "x-fastly-request-id"))  techs.add("Fastly");
  if (headerVal(headers, "fly-request-id"))       techs.add("Fly.io");
  if (headerVal(headers, "x-railway-request-id")) techs.add("Railway");
  if (headerVal(headers, "x-render-origin-server")) techs.add("Render");
  // x-served-by is set by any Varnish stack; only Fastly's POP-id shape
  // (cache-<pop><n>-<IATA>) identifies Fastly.
  if (/^cache-[a-z0-9]+-[A-Za-z]{3}/i.test(headerVal(headers, "x-served-by") ?? "")) techs.add("Fastly");
  if (headerVal(headers, "x-cache")) {
    const xc = headerVal(headers, "x-cache") ?? "";
    if (/cloudfront/i.test(xc))                   techs.add("AWS CloudFront");
  }
  const via = headerVal(headers, "via") ?? "";
  if (/cloudfront/i.test(via))                    techs.add("AWS CloudFront");
  if (/varnish/i.test(via))                       techs.add("Varnish Cache");
  if (/squid/i.test(via))                         techs.add("Squid Proxy");

  // ── X-Powered-By ─────────────────────────────────────────────────────
  const powered = headerVal(headers, "x-powered-by") ?? "";
  if (/php/i.test(powered))                       techs.add("PHP");
  if (/^express(?:$|,)/i.test(powered.trim()))    techs.add("Express.js");
  if (/asp\.net/i.test(powered))                  techs.add("ASP.NET");
  if (/^next\.js/i.test(powered.trim()))          techs.add("Next.js");
  if (/nuxt/i.test(powered))                      techs.add("Nuxt.js");
  if (/django/i.test(powered))                    techs.add("Django");
  if (/rails/i.test(powered))                     techs.add("Ruby on Rails");

  // ── Framework-specific headers ───────────────────────────────────────
  if (headerVal(headers, "x-drupal-cache") || headerVal(headers, "x-drupal-dynamic-cache")) techs.add("Drupal");
  if (headerVal(headers, "x-wordpress-cache") || headerVal(headers, "x-wp-cf-super-cache")) techs.add("WordPress");
  if (headerVal(headers, "x-shopify-stage") || headerVal(headers, "x-shopid"))              techs.add("Shopify");
  if (headerVal(headers, "x-wix-request-id"))     techs.add("Wix");
  if (headerVal(headers, "x-squarespace-cache"))  techs.add("Squarespace");
  if (headerVal(headers, "x-ghost-cache-status")) techs.add("Ghost");

  // Generator / Link headers
  const link = headerVal(headers, "link") ?? "";
  if (/wp-json|wp\.me/i.test(link))               techs.add("WordPress");
  if (/api\.ghost\.org/i.test(link))              techs.add("Ghost");
  const generator = headerVal(headers, "x-generator") ?? "";
  if (/drupal/i.test(generator))                  techs.add("Drupal");
  if (/wordpress/i.test(generator))               techs.add("WordPress");

  // ── Cookie-based detection ───────────────────────────────────────────
  const setCookie = headerVal(headers, "set-cookie") ?? "";
  if (/PHPSESSID/i.test(setCookie))               techs.add("PHP");
  if (/ASP\.NET_SessionId/i.test(setCookie))      techs.add("ASP.NET");
  if (/JSESSIONID/i.test(setCookie))              techs.add("Java / Servlet");
  if (/laravel_session/i.test(setCookie))         techs.add("Laravel");
  // csrftoken only: `sessionid` is a generic session-cookie name many stacks use.
  if (/(?:^|[\s,;])csrftoken=/i.test(setCookie))   techs.add("Django");
  if (/rack\.session/i.test(setCookie))           techs.add("Ruby on Rails");
  if (/shopify/i.test(setCookie))                 techs.add("Shopify");
  if (/__stripe/i.test(setCookie))                techs.add("Stripe");

  // ── HTML-based detection (first 80KB) ───────────────────────────────
  //
  // Evidence must be structural (see techEvidence.ts): an asset the page loads,
  // a `<meta name="generator">`, or a global used in executable script content.
  // A bare mention or an `<a href>` to a vendor's site is prose, not evidence —
  // a blog linking to shopify.com does not run on Shopify, and the CVE monitor
  // matches these names against advisories.
  const s = html.slice(0, 80_000);
  const assets = assetUrls(s);
  const js = scriptText(s);
  const gens = generators(s);
  const generatedBy = (re: RegExp) => gens.some((g) => re.test(g));
  const assetPath = (re: RegExp) => assets.some((u) => re.test(u));

  // CMS platforms
  if (generatedBy(/wordpress/i) || assetPath(/\/wp-(?:content|includes)\//i))                     techs.add("WordPress");
  if (generatedBy(/drupal/i) || /drupal\.settings|Drupal\.behaviors/i.test(js))                   techs.add("Drupal");
  if (generatedBy(/joomla/i) || assetPath(/\/media\/jui\/|(?:^|\/)(?:feed|components)\/com_/i))                                        techs.add("Joomla");
  if (generatedBy(/ghost/i))                                                                      techs.add("Ghost");
  if (loadsFromHost(assets, "cdn.shopify.com", "shopifycdn.com") || /Shopify\.theme/.test(js))    techs.add("Shopify");
  if (loadsFromHost(assets, "squarespace-cdn.com", "static1.squarespace.com") || /\sdata-squarespace/i.test(s) || generatedBy(/squarespace/i)) techs.add("Squarespace");
  if (loadsFromHost(assets, "wixstatic.com", "parastorage.com") || generatedBy(/^wix\.com/i))     techs.add("Wix");
  if (loadsFromHost(assets, "uploads-ssl.webflow.com", "website-files.com") || /\sdata-wf-(?:site|page)=/i.test(s) || generatedBy(/webflow/i)) techs.add("Webflow");

  // AI-builder / vibe-coding platforms. og:image is honoured for Lovable only: its
  // template ships an `og:image` on lovable.dev that sites rarely change. Any
  // other meta `content=` (SEO keywords, descriptions) is prose.
  const ogImages = [...s.matchAll(/<meta\b[^>]*\b(?:property|name)=["'](?:og|twitter):image["'][^>]*>/gi)]
    .map((m) => /\bcontent=["']([^"']*)/i.exec(m[0])?.[1] ?? "");
  // Base44: webappanalyzer keys on this meta tag.
  if (/<meta\b[^>]*\bname=["']apple-mobile-web-app-title["'][^>]*\bcontent=["']base44["']|<meta\b[^>]*\bcontent=["']base44["'][^>]*\bname=["']apple-mobile-web-app-title["']/i.test(s)) techs.add("Base44");
  if (loadsFromHost([...assets, ...ogImages], "lovable.app", "lovable.dev", "gptengineer.app"))   techs.add("Lovable");
  if (loadsFromHost(assets, "bolt.new", "stackblitz.io", "webcontainer.io"))                       techs.add("Bolt.new");

  // Backend-as-a-Service platforms (informational, used for agent fix routing)
  if (loadsFromHost(assets, "supabase.co", "supabase.in") || /supabase\.(?:co|in)|createClient.*supabase|SUPABASE_URL/i.test(js)) techs.add("Supabase");
  if (
    loadsFromHost(assets, "firebaseapp.com") ||
    assetPath(/gstatic\.com\/firebasejs/i) ||
    /firebaseConfig|firebaseapp\.com|firebase\.initializeApp|from\s+["']firebase\//i.test(js)
  ) techs.add("Firebase");

  // JS frameworks
  // Next.js: structural markers only. Matching the bare token `__NEXT_DATA__`
  // fired on any page that merely *mentions* it — documentation, a blog post, a
  // security report. It has to appear as the script element Next actually
  // emits, or as an assignment, rather than as prose.
  if (
    /_next\/static/i.test(s) ||
    /<script[^>]+id=["']__NEXT_DATA__["']/i.test(s) ||
    /__NEXT_DATA__\s*=/.test(s) ||
    /next\/dist/i.test(s)
  ) techs.add("Next.js");
  if (assetPath(/\/_nuxt\//i) || /\sid=["']__nuxt["']/i.test(s) || /__nuxt__|__NUXT__/i.test(js))   techs.add("Nuxt.js");
  if (/\sid=["']___gatsby["']/i.test(s) || /___gatsby|__GATSBY/i.test(js) || generatedBy(/^gatsby/i)) techs.add("Gatsby");
  if (/\sdata-reactroot\b/i.test(s) || /ReactDOM|__react(?:Fiber|Container|Props)/.test(js) || assetPath(/react(?:-dom)?\.(?:development|production)/i)) techs.add("React");
  if (/__vue_app__/i.test(s) || /\sdata-v-[a-f0-9]{8}[\s=>]/.test(s) || /Vue\.version/.test(js) || assetPath(/vue(?:\.runtime)?(?:\.global)?\.(?:min\.)?js/i)) techs.add("Vue.js");
  // An attribute or a loaded file, not the words: a tutorial that mentions ng-app or angular.js is not
  // running Angular. (`ng-app` and angular.js are AngularJS, which webappanalyzer lists apart.)
  if (/<[a-z][\w-]*\b[^>]*\sng-version\s*=/i.test(s) || /<(?:div|html|body)\b[^>]*\sng-app\b/i.test(s) || assetPath(/\bangular(?:[.-][\d.]*\d)?(?:\.min)?\.js|\/angular(?:\.min)?\.js/i) || /\bplatformBrowserDynamic\b/.test(js)) techs.add("Angular");
  // Svelte's scoped-CSS hash always carries a digit (`svelte-1abc2de`); a bare
  // `svelte-check` / `svelte-preprocess` is the tooling's name, not a class.
  if (/\bclass=["'][^"']*\bsvelte-(?=[a-z]*\d)[a-z0-9]{4,8}\b/i.test(s) || /__svelte|data-sveltekit-/i.test(s)) techs.add("Svelte");
  if (/__remixContext|remix-manifest/i.test(s))                                                    techs.add("Remix");
  // Astro emits island markers only where a component hydrates, so a fully
  // static Astro site carries neither. Key on the generator meta the official
  // template ships. A site that strips it is simply not detected — which is the
  // right outcome: reporting nothing beats reporting the wrong framework.
  if (/astro-island|astro-root/i.test(s) || generatedBy(/^Astro/i)) {
    techs.add("Astro");
  }
  if (/\sdata-ember-/i.test(s) || /Ember\.VERSION|EmberENV/.test(js) || assetPath(/\/ember(?:[.-][\w.-]*)?\.js/i)) techs.add("Ember.js");
  if (/Backbone\.View/.test(js) || assetPath(/\/backbone(?:[.-][\w.-]*)?\.js/i))                   techs.add("Backbone.js");

  // CSS frameworks
  //
  // These three used to match generic class names and were the largest source
  // of false positives in the module. `class="grid"` reported Tailwind;
  // `class="cta-row"` reported Bootstrap, because \brow finds a word boundary
  // at the hyphen. Any hand-written stylesheet using ordinary layout words was
  // credited to a framework it had never heard of — and technologies feed CVE
  // matching, so a phantom framework means alerts for advisories that cannot
  // apply. Match markers a framework actually emits.
  if (/tailwindcss/i.test(s) || countTailwindUtilities(s) >= TAILWIND_MIN_UTILITIES) {
    techs.add("Tailwind CSS");
  }
  if (
    /bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)/i.test(s) ||
    /\bdata-bs-(?:toggle|target|dismiss|ride|parent)\b/i.test(s) ||
    /\bcol-(?:xs|sm|md|lg|xl|xxl)-(?:auto|1[0-2]|[1-9])\b/.test(s) ||
    /\bnavbar-expand-(?:sm|md|lg|xl|xxl)\b/.test(s)
  ) techs.add("Bootstrap");
  if (/bulma(?:\.min)?\.css/i.test(s) || /\bcolumn\s+is-[a-z0-9-]+/i.test(s)) techs.add("Bulma");

  // JS libraries
  // Same rule as above: the library's file or its own global in executable script, never the
  // name in prose. `x-data=` in a tutorial or `_.version` in a blog post is not Alpine or Lodash,
  // and these names feed CVE matching.
  if (assetPath(/jquery(?:[.-]\d[\w.-]*)?(?:\.slim)?(?:\.min)?\.js|\/jquery@\d|ajax\.googleapis\.com\/ajax\/libs\/jquery\//i) || /\bjQuery\.fn\b/.test(js)) techs.add("jQuery");
  if (assetPath(/lodash(?:\.core)?(?:\.min)?\.js|\/lodash@\d|\/lodash\.js\//i) || /\b_\.VERSION\b|lodash\.templateSettings/.test(js)) techs.add("Lodash");
  if (assetPath(/alpinejs|\/alpine(?:\.min)?\.js/i) || /<[a-z][\w-]*\b[^>]*\sx-data(?:\s*=|[\s>])/i.test(s) || /\bAlpine\.start\(/.test(js)) techs.add("Alpine.js");
  if (assetPath(/htmx(?:\.org)?(?:@[\d.]+)?(?:\/dist)?(?:\/htmx)?(?:\.min)?\.js|\/htmx\.org/i) || /<[a-z][\w-]*\b[^>]*\shx-(?:get|post|put|patch|delete)\s*=/i.test(s)) techs.add("HTMX");

  // Analytics & tracking
  if (
    loadsFromHost(assets, "google-analytics.com") ||
    assetPath(/googletagmanager\.com\/gtag\/js/i) ||
    /\bgtag\(\s*["']config["']|GoogleAnalyticsObject|\bga\(\s*["']create["']/.test(js)
  ) techs.add("Google Analytics");
  if (assetPath(/googletagmanager\.com\/gtm\.js/i) || /<iframe\b[^>]*\ssrc=["'][^"']*googletagmanager\.com\/ns\.html/i.test(s) || /<!-- (?:End )?Google Tag Manager -->/.test(s)) techs.add("Google Tag Manager");
  // A vendor link or mention is not a vendor script: require the script it
  // serves (or its init call in executable content), never `<a href>` or prose.
  if (loadsFromHost(assets, "plausible.io") || /<script\b[^>]*\bdata-domain=[^>]*plausible|<script\b[^>]*plausible[^>]*\bdata-domain=/i.test(s)) techs.add("Plausible Analytics");
  if (loadsFromHost(assets, "mixpanel.com", "mxpnl.com") || /mixpanel\.init/.test(js))            techs.add("Mixpanel");
  if (loadsFromHost(assets, "segment.com", "segment.io") || /analytics\.load\(|analytics\.page\(/.test(js)) techs.add("Segment");
  if (loadsFromHost(assets, "hotjar.com") || /\bhjid\b|static\.hotjar\.com/.test(js))            techs.add("Hotjar");
  if (loadsFromHost(assets, "intercom.io", "intercomcdn.com") || /intercomSettings/.test(js))     techs.add("Intercom");
  if (loadsFromHost(assets, "js.stripe.com") || /\bStripe\(/.test(js))                            techs.add("Stripe");
  if (loadsFromHost(assets, "sentry.io", "sentry-cdn.com") || /Sentry\.init\(|ingest\.sentry\.io/.test(js)) techs.add("Sentry");

  // Static site generators (meta generator tag)
  if (generatedBy(/hugo/i))                                                                       techs.add("Hugo");
  if (generatedBy(/jekyll/i))                                                                     techs.add("Jekyll");
  if (generatedBy(/eleventy/i))                                                                   techs.add("Eleventy");
  if (generatedBy(/hexo/i))                                                                       techs.add("Hexo");

  // Language indicators. The old fallback matched the words python|flask|
  // fastapi|django anywhere on an otherwise-unrecognised page, so a tutorial
  // about Python was reported as running it. Match what a Python stack emits: a
  // traceback, the Werkzeug/Django debug pages, and Django's CSRF form field.
  if (/Traceback \(most recent call last\)|You're seeing this error because you have <code>DEBUG = True|Werkzeug Debugger/.test(s)) techs.add("Python");
  if (/name=["']csrfmiddlewaretoken["']/i.test(s))                                                techs.add("Django");
  // Rails: match structural markers only. The old `rack` substring matched
  // "tracking" (Tailwind's tracking-* utilities), "bracket", "crack", etc. —
  // firing on nearly every styled page. Use Rails-specific signals instead:
  // the authenticity_token CSRF field/meta, the csrf-param meta, or the
  // capitalised Rack:: middleware namespace as it appears in Rack error pages.
  if (
    generatedBy(/ruby on rails/i) ||
    /name=["']authenticity_token["']/i.test(s) ||
    /name=["']csrf-param["']/i.test(s) ||
    /\bRack::[A-Z]/.test(s)
  ) techs.add("Ruby on Rails");

  return [...techs];
}
