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
}

const SITE = (process.env["APP_ORIGIN"] ?? "https://secscan.us").replace(/\/$/, "");

const ROUTES: { match: RegExp; meta: (path: string) => PageMeta }[] = [
  {
    match: /^\/learn\/?$/,
    meta: () => ({
      path: "/learn",
      title: "Security Documentation — SecScan",
      description:
        "Plain-English explanations of every security check SecScan runs: HTTPS, HSTS, CSP, X-Frame-Options, CORS, cookie flags, Supabase RLS, and more. With code fixes.",
    }),
  },
  {
    match: /^\/privacy\/?$/,
    meta: () => ({
      path: "/privacy",
      title: "Privacy Policy — SecScan",
      description:
        "What SecScan collects when you run a scan, who it is shared with, how long it is kept, and how to have it deleted.",
    }),
  },
  {
    match: /^\/terms\/?$/,
    meta: () => ({
      path: "/terms",
      title: "Terms of Service — SecScan",
      description:
        "The terms that apply when you use SecScan, including what you are permitted to scan.",
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
    }),
  },

  // Everything below is private, thin, or both. A signed-in page has nothing to
  // offer a searcher, and a sign-in form on an indexed URL is the shape that
  // gets a domain flagged as deceptive.
  { match: /^\/dashboard\/?$/, meta: () => ({ path: "/dashboard", title: "Dashboard — SecScan", noindex: true }) },
  { match: /^\/scan\/?$/, meta: () => ({ path: "/scan", title: "New scan — SecScan", noindex: true }) },
  { match: /^\/scan\/[A-Za-z0-9_-]+\/?$/, meta: (p) => ({ path: p, title: "Scan in progress — SecScan", noindex: true }) },
  { match: /^\/monitor\/?$/, meta: () => ({ path: "/monitor", title: "Monitor — SecScan", noindex: true }) },
  { match: /^\/domains\/?$/, meta: () => ({ path: "/domains", title: "Verified domains — SecScan", noindex: true }) },
  { match: /^\/settings\/?$/, meta: () => ({ path: "/settings", title: "Settings — SecScan", noindex: true }) },
  { match: /^\/sign-in\/?$/, meta: () => ({ path: "/sign-in", title: "Sign in — SecScan", noindex: true }) },
  { match: /^\/register\/?$/, meta: () => ({ path: "/register", title: "Create an account — SecScan", noindex: true }) },
  { match: /^\/forgot-password\/?$/, meta: () => ({ path: "/forgot-password", title: "Reset your password — SecScan", noindex: true }) },
  { match: /^\/reset-password\/?$/, meta: () => ({ path: "/reset-password", title: "Choose a new password — SecScan", noindex: true }) },
  { match: /^\/verify-email\/?$/, meta: () => ({ path: "/verify-email", title: "Confirming your email — SecScan", noindex: true }) },

  // A report and a share link both point at somebody's scan findings. The share
  // link is meant to be openable by whoever holds it — that is not the same as
  // being listed in search results for anyone to find.
  {
    match: /^\/report\/[A-Za-z0-9_-]+\/?$/,
    meta: (p) => ({ path: p, title: "Security report — SecScan", noindex: true }),
  },
  {
    match: /^\/share\/[A-Za-z0-9_-]+\/?$/,
    meta: (p) => ({ path: p, title: "Shared security report — SecScan", noindex: true }),
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

/**
 * Rewrite the shell's head for one route.
 *
 * Tags are replaced, not appended: a second <link rel="canonical"> alongside
 * the original leaves the crawler to choose, and it may choose the one being
 * overridden.
 */
export function applyPageMeta(html: string, meta: PageMeta): string {
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
  }

  if (meta.noindex) {
    out = out.replace(
      /<meta\s+name="robots"\s+content="[^"]*"\s*\/?>/i,
      '<meta name="robots" content="noindex, nofollow" />',
    );
  }

  return out;
}
