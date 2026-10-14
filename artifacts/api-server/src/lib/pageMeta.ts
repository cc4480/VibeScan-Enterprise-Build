/**
 * Per-route <head> metadata for the SPA shell.
 *
 * Every route was served the same built index.html, so every URL carried
 * <link rel="canonical" href="https://secscan.us/">. That tells a search engine
 * /learn, /privacy and /terms are duplicates of the homepage and should not be
 * indexed separately — seclayer.app had the identical bug and Search Console
 * reported exactly that, as "Discovered - currently not indexed".
 *
 * It also meant every private page — dashboard, settings, reports, share links,
 * sign-in — was handed to crawlers as "index, follow", contradicting the
 * noindex the client sets after hydration. A crawler acts on the HTML it
 * receives; it cannot be relied on to render JavaScript first, and for an
 * unindexed URL it may never render it at all.
 *
 * Keep the route list in sync with lib/spaRoutes.ts.
 */

export interface PageMeta {
  path: string;
  title?: string;
  description?: string;
  noindex?: boolean;
  /** Trail from home to this page, excluding home. Drives BreadcrumbList. */
  breadcrumb?: { name: string; path: string }[];
  /** schema.org type for the page node, when it is more specific than WebPage. */
  pageType?: "AboutPage";
  /** Adds a TechArticle node: the page is documentation, last reviewed on this ISO date. */
  article?: { dateModified: string };
  /** Question and answer pairs, written out as FAQPage markup. */
  faq?: { q: string; a: string }[];
}

/** One documented check, as written by the frontend build (see checkManifest in the page data). */
export interface CheckMeta {
  id: string;
  title: string;
  description: string;
  name: string;
  what: string;
  fix: string;
}

const CHECKS = new Map<string, CheckMeta>();

/** Load the list of /learn/<id> pages. Called once at startup with the build's checks.json. */
export function registerChecks(list: CheckMeta[]): void {
  CHECKS.clear();
  for (const c of list) CHECKS.set(c.id, c);
}

/** Date the documentation was last reviewed: LEARN_LAST_REVIEWED in the frontend (a test keeps them equal). */
const LEARN_REVIEWED = "2026-09-24";

const SITE = (process.env["APP_ORIGIN"] ?? "https://secscan.us").replace(/\/$/, "");

const ROUTES: { match: RegExp; meta: (path: string) => PageMeta }[] = [
  {
    match: /^\/learn\/?$/,
    meta: () => ({
      path: "/learn",
      title: "Security Documentation — SecScan.us",
      description:
        "Plain-English guides to the key security checks SecScan runs: HTTPS, HSTS, CSP, CORS, cookie flags and Supabase RLS, each with a code fix to paste.",
      breadcrumb: [{ name: "Security documentation", path: "/learn" }],
      // Same date as LEARN_LAST_REVIEWED in the page (a test keeps them equal).
      article: { dateModified: LEARN_REVIEWED },
    }),
  },
  {
    match: /^\/learn\/([a-z0-9-]+)\/?$/,
    meta: (p) => {
      const c = CHECKS.get(/^\/learn\/([a-z0-9-]+)/.exec(p)?.[1] ?? "");
      // Not a documented check: say nothing to a search engine about it. The server
      // answers 404 for these before it gets here; this covers the lenient case.
      if (!c) return { path: p, title: "Page not found — SecScan.us", noindex: true };
      return {
        path: `/learn/${c.id}`,
        title: c.title,
        description: c.description,
        breadcrumb: [
          { name: "Security documentation", path: "/learn" },
          { name: c.name, path: `/learn/${c.id}` },
        ],
        article: { dateModified: LEARN_REVIEWED },
        faq: [
          { q: `What is ${c.name}?`, a: c.what },
          { q: `How do I fix ${c.name}?`, a: c.fix },
        ],
      };
    },
  },
  {
    match: /^\/privacy\/?$/,
    meta: () => ({
      path: "/privacy",
      title: "Privacy Policy — SecScan.us",
      description:
        "What SecScan collects when you run a scan, who it is shared with, how long it is kept, and how to have it deleted.",
      breadcrumb: [{ name: "Privacy policy", path: "/privacy" }],
    }),
  },
  {
    match: /^\/terms\/?$/,
    meta: () => ({
      path: "/terms",
      title: "Terms of Service — SecScan.us",
      description:
        "The terms that apply when you use SecScan, including what you are permitted to scan.",
      breadcrumb: [{ name: "Terms of service", path: "/terms" }],
    }),
  },
  {
    // Indexable on purpose: a site owner who finds the bot in their logs
    // searches the User-Agent or the URL, and this is the page that should
    // answer them.
    match: /^\/bot\/?$/,
    meta: () => ({
      path: "/bot",
      title: "SecScan Security Bot — secscan.us/bot",
      description:
        "What the SecScan scanner is, how to recognise it in your logs by its User-Agent, and how to allow it to scan a site you own.",
      breadcrumb: [{ name: "SecScan bot", path: "/bot" }],
    }),
  },

  {
    match: /^\/about\/?$/,
    meta: () => ({
      path: "/about",
      title: "About SecScan.us — Carlos Cuellar, founder",
      description:
        "Meet Carlos Cuellar, the self-taught builder behind SecScan, and the promises the scanner keeps: report what it found, and say plainly what it didn't test.",
      breadcrumb: [{ name: "About", path: "/about" }],
      pageType: "AboutPage",
    }),
  },

  // Everything below is private, thin, or both. A signed-in page has nothing to
  // offer a searcher, and a sign-in form on an indexed URL is the shape that
  // gets a domain flagged as deceptive.
  { match: /^\/dashboard\/?$/, meta: () => ({ path: "/dashboard", title: "Dashboard — SecScan.us", noindex: true }) },
  { match: /^\/scan\/?$/, meta: () => ({ path: "/scan", title: "New scan — SecScan.us", noindex: true }) },
  { match: /^\/scan\/[A-Za-z0-9_-]+\/?$/, meta: (p) => ({ path: p, title: "Scan in progress — SecScan.us", noindex: true }) },
  { match: /^\/monitor\/?$/, meta: () => ({ path: "/monitor", title: "Monitor — SecScan.us", noindex: true }) },
  { match: /^\/domains\/?$/, meta: () => ({ path: "/domains", title: "Verified domains — SecScan.us", noindex: true }) },
  { match: /^\/settings\/?$/, meta: () => ({ path: "/settings", title: "Settings — SecScan.us", noindex: true }) },
  { match: /^\/feedback\/?$/, meta: () => ({ path: "/feedback", title: "Feedback — SecScan.us", noindex: true }) },
  { match: /^\/sign-in\/?$/, meta: () => ({ path: "/sign-in", title: "Sign in — SecScan.us", noindex: true }) },
  { match: /^\/register\/?$/, meta: () => ({ path: "/register", title: "Create an account — SecScan.us", noindex: true }) },
  { match: /^\/forgot-password\/?$/, meta: () => ({ path: "/forgot-password", title: "Reset your password — SecScan.us", noindex: true }) },
  { match: /^\/reset-password\/?$/, meta: () => ({ path: "/reset-password", title: "Choose a new password — SecScan.us", noindex: true }) },
  { match: /^\/verify-email\/?$/, meta: () => ({ path: "/verify-email", title: "Confirming your email — SecScan.us", noindex: true }) },
  { match: /^\/oauth\/authorize\/?$/, meta: () => ({ path: "/oauth/authorize", title: "Connect an app — SecScan.us", noindex: true }) },

  // A report and a share link both point at somebody's scan findings. The share
  // link is meant to be openable by whoever holds it — that is not the same as
  // being listed in search results for anyone to find.
  {
    match: /^\/report\/[A-Za-z0-9_-]+\/?$/,
    meta: (p) => ({ path: p, title: "Security report — SecScan.us", noindex: true }),
  },
  {
    match: /^\/share\/[A-Za-z0-9_-]+\/?$/,
    meta: (p) => ({ path: p, title: "Shared security report — SecScan.us", noindex: true }),
  },
];

/** Null for the homepage, whose built metadata is already correct. */
export function metaForPath(path: string): PageMeta | null {
  for (const r of ROUTES) {
    if (r.match.test(path)) return r.meta(path);
  }
  return null;
}

function escapeAttr(v: string): string {
  return v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const LD_BLOCK = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/i;

/**
 * Point the structured data at the route being served.
 *
 * The shell carries one @graph describing the homepage, and it was sent
 * unchanged on every route. So /learn returned a canonical of /learn next to a
 * WebPage node asserting "url": "https://secscan.us/" — the two tags
 * contradict each other, and the graph is the more specific claim of the pair.
 * Worse on the private routes, which were handed a FAQPage and an Offer while
 * also being marked noindex.
 *
 * Nodes describing the site rather than the page (Organization, WebSite,
 * SoftwareApplication) are true everywhere and stay. The page-scoped ones are
 * rewritten, and the homepage-only marketing nodes are dropped elsewhere.
 */
function applyJsonLd(html: string, meta: PageMeta, url: string): string {
  const block = LD_BLOCK.exec(html);
  if (!block?.[1]) return html;

  let graph: Record<string, unknown>[];
  try {
    const parsed = JSON.parse(block[1]) as { "@graph"?: Record<string, unknown>[] };
    if (!Array.isArray(parsed["@graph"])) return html;
    graph = parsed["@graph"];
  } catch {
    // Malformed JSON-LD in the shell is a build problem, not a request problem.
    // Serving the page without touching it beats serving a 500.
    return html;
  }

  // A private page makes no claim to search engines at all. Emitting an Offer
  // and eight FAQ answers under a noindex header is a mixed signal at best.
  if (meta.noindex) return html.replace(LD_BLOCK, "");

  const isHome = url === SITE || url === `${SITE}/`;

  const next = graph.flatMap((node) => {
    const type = node["@type"];

    // Homepage-specific. The pitch, the price and the how-to belong on the page
    // that makes them, not on the terms of service.
    if (!isHome && (type === "FAQPage" || type === "HowTo" || type === "SoftwareApplication")) {
      return [];
    }

    if (type === "WebPage") {
      return [
        {
          ...node,
          ...(meta.pageType ? { "@type": meta.pageType } : {}),
          ...(meta.pageType === "AboutPage" ? { about: { "@id": `${SITE}/#organization` } } : {}),
          "@id": `${url}#webpage`,
          url,
          ...(meta.title ? { name: meta.title } : {}),
          ...(meta.description ? { description: meta.description } : {}),
          inLanguage: "en-US",
          breadcrumb: {
            "@type": "BreadcrumbList",
            itemListElement: [
              { "@type": "ListItem", position: 1, name: "Home", item: `${SITE}/` },
              ...(meta.breadcrumb ?? []).map((c, i) => ({
                "@type": "ListItem",
                position: i + 2,
                name: c.name,
                item: `${SITE}${c.path}`,
              })),
            ],
          },
        },
      ];
    }

    return [node];
  });

  // The documentation is an article by the founder, which is what lets an answer
  // engine attribute and date what it quotes. Added after the page node it describes.
  if (meta.article) {
    next.push({
      "@type": "TechArticle",
      "@id": `${url}#article`,
      headline: meta.title ?? "Security documentation",
      ...(meta.description ? { description: meta.description } : {}),
      url,
      inLanguage: "en-US",
      dateModified: meta.article.dateModified,
      author: { "@id": `${SITE}/#founder` },
      publisher: { "@id": `${SITE}/#organization` },
      isPartOf: { "@id": `${url}#webpage` },
      mainEntityOfPage: { "@id": `${url}#webpage` },
    });
  }

  if (meta.faq?.length) {
    next.push({
      "@type": "FAQPage",
      "@id": `${url}#faq`,
      mainEntity: meta.faq.map((f) => ({
        "@type": "Question",
        name: f.q,
        acceptedAnswer: { "@type": "Answer", text: f.a },
      })),
    });
  }

  const json = JSON.stringify({ "@context": "https://schema.org", "@graph": next });
  // `</script>` inside a JSON string would close this block early.
  return html.replace(
    LD_BLOCK,
    `<script type="application/ld+json">${json.replace(/<\//g, "<\\/")}</script>`,
  );
}

/**
 * Rewrite the shell's head for one route.
 *
 * Tags are replaced, not appended: a second <link rel="canonical"> alongside
 * the original leaves the crawler to choose, and it may choose the one being
 * overridden.
 *
 * `extraHtml` is trusted markup produced by our own build (the prerendered
 * page body); it goes into the <noscript> block for readers that run no scripts.
 */
export function applyPageMeta(html: string, meta: PageMeta, extraHtml?: string): string {
  const url = `${SITE}${meta.path.replace(/\/$/, "") || "/"}`;
  let out = html.replace(
    /<link\s+rel="canonical"\s+href="[^"]*"\s*\/?>/i,
    `<link rel="canonical" href="${url}" />`,
  ).replace(
    /<meta\s+property="og:url"\s+content="[^"]*"\s*\/?>/i,
    `<meta property="og:url" content="${url}" />`,
  );

  if (meta.title) {
    const t = escapeAttr(meta.title);
    out = out
      .replace(/<title>[\s\S]*?<\/title>/i, `<title>${t}</title>`)
      .replace(/<meta\s+property="og:title"\s+content="[^"]*"\s*\/?>/i, `<meta property="og:title" content="${t}" />`)
      .replace(/<meta\s+name="twitter:title"\s+content="[^"]*"\s*\/?>/i, `<meta name="twitter:title" content="${t}" />`);
  }

  if (meta.description) {
    const d = escapeAttr(meta.description);
    out = out
      .replace(/<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i, `<meta name="description" content="${d}" />`)
      .replace(/<meta\s+property="og:description"\s+content="[^"]*"\s*\/?>/i, `<meta property="og:description" content="${d}" />`)
      .replace(/<meta\s+name="twitter:description"\s+content="[^"]*"\s*\/?>/i, `<meta name="twitter:description" content="${d}" />`);

    // Give a non-JS crawler this route's actual subject, not just the
    // homepage's noscript copy repeated under a different <title>. Skipped
    // for noindex routes, which have no description above to reach here.
    if (!meta.noindex) {
      const t = meta.title ? escapeAttr(meta.title) : "";
      out = out.replace(
        /(<p>SecScan needs JavaScript to run a scan interactively\. These pages read fine without it:<\/p>)/,
        // A function, so a `$` in the markup is never read as a replacement pattern.
        (marker) => `${t ? `<h2>${t}</h2>\n      ` : ""}<p>${d}</p>\n      ${extraHtml ? `${extraHtml}\n      ` : ""}${marker}`,
      );
    }
  }

  if (meta.noindex) {
    out = out.replace(
      /<meta\s+name="robots"\s+content="[^"]*"\s*\/?>/i,
      '<meta name="robots" content="noindex, nofollow" />',
    );
  }

  return applyJsonLd(out, meta, url);
}

/**
 * Put a page's rendered markup inside the empty app container.
 *
 * The fragment is what scripts/prerender-public.mjs read back out of #root in
 * headless Chromium at build time, so a reader that runs no JavaScript gets the
 * page itself, not an empty div. React's createRoot replaces the container's
 * contents when it starts, so nothing here has to be reconciled — the markup is
 * simply what the page looks like until then. Trusted: produced by our own build.
 * Returns the HTML untouched if the shell has no empty container to fill.
 */
export function withRenderedRoot(html: string, fragment: string | undefined): string {
  if (!fragment) return html;
  // A function, so a `$` in the markup is never read as a replacement pattern.
  return html.replace('<div id="root"></div>', () => `<div id="root">${fragment}</div>`);
}

/** Routes that have a prerendered page, and the name of its fragment file. */
export const PRERENDERED: Record<string, string> = {
  "/": "home",
  "/learn": "learn",
  "/about": "about",
  "/bot": "bot",
  "/privacy": "privacy",
  "/terms": "terms",
};
