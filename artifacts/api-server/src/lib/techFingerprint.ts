/**
 * Technology fingerprint detection.
 * Inspects HTTP response headers and HTML to identify the frameworks,
 * CDNs, and platforms the target site uses.
 *
 * Extracted from scanner.ts to keep the main scanner file focused on
 * orchestration and vulnerability analysis.
 */

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
  if (/apache/i.test(server))                     techs.add("Apache");
  if (/microsoft-iis/i.test(server))              techs.add("IIS");
  if (/cloudflare/i.test(server))                 techs.add("Cloudflare");
  if (/vercel/i.test(server))                     techs.add("Vercel");
  if (/fastly/i.test(server))                     techs.add("Fastly");
  if (/litespeed/i.test(server))                  techs.add("LiteSpeed");
  if (/openresty/i.test(server))                  techs.add("OpenResty");
  if (/caddy/i.test(server))                      techs.add("Caddy");
  if (/gunicorn/i.test(server))                   techs.add("Gunicorn");
  if (/unicorn/i.test(server))                    techs.add("Unicorn");
  if (/cowboy/i.test(server))                     techs.add("Cowboy");
  if (/kestrel/i.test(server))                    techs.add("Kestrel (.NET)");
  if (/gfe|google frontend/i.test(server))        techs.add("Google Cloud / GFE");
  if (/aws|amazon/i.test(server))                 techs.add("AWS");
  if (/envoy/i.test(server))                      techs.add("Envoy Proxy");
  if (/netlify/i.test(server))                    techs.add("Netlify");
  if (/squarespace/i.test(server))                techs.add("Squarespace");
  if (/ghost/i.test(server))                      techs.add("Ghost");
  if (/webflow/i.test(server))                    techs.add("Webflow");

  // ── CDN / infrastructure headers ─────────────────────────────────────
  if (headerVal(headers, "cf-ray"))               techs.add("Cloudflare");
  if (headerVal(headers, "cf-cache-status"))      techs.add("Cloudflare");
  if (headerVal(headers, "x-vercel-id"))          techs.add("Vercel");
  if (headerVal(headers, "x-netlify"))            techs.add("Netlify");
  if (headerVal(headers, "x-amz-cf-id") || headerVal(headers, "x-amz-request-id")) techs.add("AWS CloudFront");
  if (headerVal(headers, "x-azure-ref"))          techs.add("Azure");
  if (headerVal(headers, "x-ms-request-id"))      techs.add("Azure");
  if (headerVal(headers, "x-github-request-id"))  techs.add("GitHub Pages");
  if (headerVal(headers, "x-fastly-request-id"))  techs.add("Fastly");
  if (headerVal(headers, "fly-request-id"))       techs.add("Fly.io");
  if (headerVal(headers, "x-railway-request-id")) techs.add("Railway");
  if (headerVal(headers, "x-render-origin-server")) techs.add("Render");
  if (headerVal(headers, "x-served-by"))          techs.add("Fastly");
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
  if (/express/i.test(powered))                   techs.add("Express.js");
  if (/asp\.net/i.test(powered))                  techs.add("ASP.NET");
  if (/next\.js/i.test(powered))                  techs.add("Next.js");
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
  if (/csrftoken|sessionid/i.test(setCookie))     techs.add("Django");
  if (/rack\.session/i.test(setCookie))           techs.add("Ruby on Rails");
  if (/shopify/i.test(setCookie))                 techs.add("Shopify");
  if (/__stripe/i.test(setCookie))                techs.add("Stripe");

  // ── HTML-based detection (first 80KB) ───────────────────────────────
  const s = html.slice(0, 80_000);

  // CMS platforms
  if (/<meta[^>]*generator[^>]*wordpress/i.test(s) || /wp-content|wp-includes|wpemoji/i.test(s))  techs.add("WordPress");
  if (/<meta[^>]*generator[^>]*drupal/i.test(s) || /drupal\.settings|Drupal\.behaviors/i.test(s)) techs.add("Drupal");
  if (/<meta[^>]*generator[^>]*joomla/i.test(s) || /\/media\/jui\//i.test(s))                     techs.add("Joomla");
  if (/<meta[^>]*generator[^>]*ghost/i.test(s) || /ghost\.org|content="Ghost/i.test(s))           techs.add("Ghost");
  if (/shopify\.com|cdn\.shopify\.com|Shopify\.theme/i.test(s))                                   techs.add("Shopify");
  if (/squarespace\.com|squarespace-cdn|data-squarespace/i.test(s))                               techs.add("Squarespace");
  if (/wix\.com|static\.wixstatic|wixsite\.com/i.test(s))                                         techs.add("Wix");
  if (/webflow\.com|uploads-ssl\.webflow/i.test(s))                                               techs.add("Webflow");

  // AI-builder / vibe-coding platforms
  if (/(?:src|href|content)=["'][^"']*(?:lovable\.(?:app|dev)|gptengineer\.app)|https?:\/\/[^"'\s]*lovable\.(?:app|dev)/i.test(s))  techs.add("Lovable");
  if (/(?:src|href|content)=["'][^"']*(?:bolt\.new|stackblitz\.io|webcontainer\.io)|https?:\/\/[^"'\s]*(?:bolt\.new|stackblitz\.io)/i.test(s)) techs.add("Bolt.new");

  // Backend-as-a-Service platforms (informational, used for agent fix routing)
  if (/supabase\.co|supabase\.in|createClient.*supabase|SUPABASE_URL/i.test(s))                   techs.add("Supabase");
  if (/firebase\.google\.com|firebaseapp\.com|initializeApp|firebaseConfig/i.test(s))             techs.add("Firebase");

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
  if (/__nuxt__|nuxt\.js|_nuxt\//i.test(s))                                                       techs.add("Nuxt.js");
  if (/gatsby|___gatsby|__GATSBY/i.test(s))                                                       techs.add("Gatsby");
  if (/data-reactroot|ReactDOM|react\.development|react\.production|__react_/i.test(s))           techs.add("React");
  if (/__vue_app__|data-v-[a-f0-9]{8}|Vue\.version|vue\.min\.js/i.test(s))                        techs.add("Vue.js");
  if (/ng-version|ng-app|angular\.js|angular\.min\.js|platformBrowserDynamic/i.test(s))           techs.add("Angular");
  if (/svelte-[a-z0-9]+|__svelte|SvelteKit/i.test(s))                                             techs.add("Svelte");
  if (/__remixContext|remix-manifest/i.test(s))                                                    techs.add("Remix");
  // Astro emits island markers only where a component hydrates, so a fully
  // static Astro site carries neither. Key on the generator meta the official
  // template ships. A site that strips it is simply not detected — which is the
  // right outcome: reporting nothing beats reporting the wrong framework.
  if (/astro-island|astro-root/i.test(s) || /<meta[^>]*generator[^>]*content=["']Astro/i.test(s)) {
    techs.add("Astro");
  }
  if (/data-ember-|emberjs|Ember\.VERSION/i.test(s))                                              techs.add("Ember.js");
  if (/backbone\.js|Backbone\.View/i.test(s))                                                     techs.add("Backbone.js");

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
  if (/jquery[.-][0-9]|jquery\.min\.js|jQuery\.fn/i.test(s))                                     techs.add("jQuery");
  if (/lodash\.js|lodash\.min|_\.version/i.test(s))                                               techs.add("Lodash");
  if (/alpinejs|x-data=|x-show=/i.test(s))                                                        techs.add("Alpine.js");
  if (/htmx\.org|hx-get|hx-post/i.test(s))                                                        techs.add("HTMX");

  // Analytics & tracking
  if (/google-analytics\.com|gtag\(|ga\.js|GoogleAnalyticsObject/i.test(s))                      techs.add("Google Analytics");
  if (/googletagmanager\.com\/gtm/i.test(s))                                                      techs.add("Google Tag Manager");
  if (/plausible\.io|data-domain/i.test(s) && /plausible/i.test(s))                              techs.add("Plausible Analytics");
  if (/mixpanel\.com|mixpanel\.init/i.test(s))                                                    techs.add("Mixpanel");
  if (/segment\.com|analytics\.load|analytics\.page/i.test(s))                                   techs.add("Segment");
  if (/hotjar\.com|hjid/i.test(s))                                                                techs.add("Hotjar");
  if (/intercom\.io|intercomSettings/i.test(s))                                                   techs.add("Intercom");
  if (/js\.stripe\.com|Stripe\(/i.test(s))                                                        techs.add("Stripe");
  if (/sentry\.io|Sentry\.init/i.test(s))                                                         techs.add("Sentry");

  // Static site generators (meta generator tag)
  if (/<meta[^>]*generator[^>]*hugo/i.test(s))                                                    techs.add("Hugo");
  if (/<meta[^>]*generator[^>]*jekyll/i.test(s))                                                  techs.add("Jekyll");
  if (/<meta[^>]*generator[^>]*eleventy/i.test(s))                                                techs.add("Eleventy");
  if (/<meta[^>]*generator[^>]*hexo/i.test(s))                                                    techs.add("Hexo");

  // Language indicators from error messages / comments
  if (/python|django|flask|fastapi/i.test(s) && techs.size === 0)                                 techs.add("Python");
  // Rails: match structural markers only. The old `rack` substring matched
  // "tracking" (Tailwind's tracking-* utilities), "bracket", "crack", etc. —
  // firing on nearly every styled page. Use Rails-specific signals instead:
  // the authenticity_token CSRF field/meta, the csrf-param meta, or the
  // capitalised Rack:: middleware namespace as it appears in Rack error pages.
  if (
    /ruby on rails/i.test(s) ||
    /name=["']authenticity_token["']/i.test(s) ||
    /name=["']csrf-param["']/i.test(s) ||
    /\bRack::[A-Z]/.test(s)
  ) techs.add("Ruby on Rails");

  return [...techs];
}
