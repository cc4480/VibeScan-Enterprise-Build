import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { metaForPath, applyPageMeta, withRenderedRoot, PRERENDERED } from "./pageMeta";
import { SPA_ROUTES } from "./spaRoutes";

const SHELL = `<!doctype html><html><head>
<title>SecScan — Black-Box Security Scanning for Vibe Coders</title>
<meta name="description" content="Paste a URL and get a report." />
<meta name="robots" content="index, follow" />
<link rel="canonical" href="https://secscan.us/" />
<meta property="og:title" content="SecScan" />
<meta property="og:description" content="Old description." />
<meta property="og:url" content="https://secscan.us/" />
<meta name="twitter:title" content="SecScan" />
<meta name="twitter:description" content="Old twitter description." />
</head><body></body></html>`;

// Shaped like the real built index.html's <body>, which the plain SHELL above
// doesn't have — the noscript-rewrite tests need the actual paragraph the
// rewrite matches against.
const SHELL_WITH_NOSCRIPT = `<!doctype html><html><head>
<title>SecScan</title>
<meta name="description" content="Old." />
<meta name="robots" content="index, follow" />
<link rel="canonical" href="https://secscan.us/" />
</head><body>
<noscript>
  <h1>SecScan — black-box security scanning for vibe coders</h1>
  <p>Paste a URL for a web application you own or are authorised to test.</p>
  <p>SecScan needs JavaScript to run a scan interactively. These pages read fine without it:</p>
  <nav><ul><li><a href="/">Home</a></li></ul></nav>
</noscript>
<div id="root"></div>
</body></html>`;

describe("page metadata", () => {
  it("leaves the homepage to its built metadata", () => {
    expect(metaForPath("/")).toBeNull();
  });

  it("gives each indexable page its own canonical instead of the homepage", () => {
    // The bug this fixes: every URL claimed the homepage as canonical, so
    // Google treated them as duplicates and declined to index them.
    for (const [path, expected] of [
      ["/learn", "https://secscan.us/learn"],
      ["/privacy", "https://secscan.us/privacy"],
      ["/terms", "https://secscan.us/terms"],
    ] as const) {
      const html = applyPageMeta(SHELL, metaForPath(path)!);
      expect(html, path).toContain(`<link rel="canonical" href="${expected}" />`);
      expect(html, path).not.toContain('canonical" href="https://secscan.us/"');
    }
  });

  it("keeps indexable pages indexable", () => {
    for (const path of ["/learn", "/privacy", "/terms"]) {
      expect(applyPageMeta(SHELL, metaForPath(path)!), path).toContain('content="index, follow"');
    }
  });

  it("marks every private page noindex", () => {
    // These were all being handed to crawlers as index,follow, contradicting
    // the noindex the client sets only after hydration.
    for (const path of [
      "/dashboard",
      "/scan",
      "/scan/abc123",
      "/monitor",
      "/domains",
      "/settings",
      "/sign-in",
      "/register",
      "/forgot-password",
      "/reset-password",
      "/verify-email",
      "/report/abc123",
      "/share/Xy_9-Zq",
    ]) {
      const meta = metaForPath(path);
      expect(meta, path).not.toBeNull();
      expect(meta!.noindex, path).toBe(true);
      expect(applyPageMeta(SHELL, meta!), path).toContain('content="noindex, nofollow"');
    }
  });

  it("gives a non-JS crawler on /learn that route's subject, not just the homepage noscript copy", () => {
    const html = applyPageMeta(SHELL_WITH_NOSCRIPT, metaForPath("/learn")!);
    expect(html).toContain("<h2>Security Documentation — SecScan.us</h2>");
    expect(html).toContain("<p>Plain-English guides to the key security checks SecScan runs");
    // Still ahead of the nav, so it doesn't look tacked on after the links.
    expect(html.indexOf("<h2>Security Documentation")).toBeLessThan(html.indexOf("<nav>"));
  });

  it("adds the prerendered body to /learn's noscript, before the nav, and keeps $ characters literal", () => {
    const body = "<section><h2>HTTPS</h2><pre>echo $1 $& $$ $'</pre></section>";
    const html = applyPageMeta(SHELL_WITH_NOSCRIPT, metaForPath("/learn")!, body);
    expect(html).toContain(body);
    expect(html.indexOf(body)).toBeLessThan(html.indexOf("<nav>"));
    expect(applyPageMeta(SHELL_WITH_NOSCRIPT, metaForPath("/learn")!)).not.toContain("<section>");
  });

  it("leaves noindex routes out of the noscript rewrite", () => {
    const meta = metaForPath("/dashboard")!;
    expect(applyPageMeta(SHELL_WITH_NOSCRIPT, meta)).not.toContain("<h2>");
  });

  it("does not leave a trailing slash in the canonical", () => {
    expect(applyPageMeta(SHELL, metaForPath("/privacy/")!)).toContain('href="https://secscan.us/privacy"');
  });

  it("updates og and twitter tags alongside the canonical", () => {
    const html = applyPageMeta(SHELL, metaForPath("/learn")!);
    expect(html).toContain('og:url" content="https://secscan.us/learn"');
    expect(html).toContain('og:title" content="Security Documentation — SecScan.us"');
    expect(html).not.toContain("Old description.");
    expect(html).not.toContain("Old twitter description.");
  });

  it("covers every route the shell is served for", () => {
    // A route that reaches the shell without an entry here inherits the
    // homepage canonical again, which is the whole bug. The homepage is the
    // one deliberate exception.
    const samples = [
      "/", "/dashboard", "/scan", "/scan/abc", "/report/abc", "/share/abc",
      "/monitor", "/learn", "/domains", "/settings", "/privacy", "/terms",
      "/sign-in", "/register", "/forgot-password", "/reset-password", "/verify-email",
    ];
    for (const path of samples) {
      expect(SPA_ROUTES.some((re) => re.test(path)), `${path} should be an SPA route`).toBe(true);
      if (path !== "/") {
        expect(metaForPath(path), `${path} has no metadata entry`).not.toBeNull();
      }
    }
  });
});

/**
 * The structured data used to describe the homepage on every URL, which
 * contradicts the canonical tag sitting next to it. The graph is the more
 * specific of the two claims, so it has to be the one that moves.
 */
const SHELL_WITH_LD = `<!doctype html><html><head>
<title>SecScan</title>
<meta name="description" content="Old." />
<meta name="robots" content="index, follow" />
<link rel="canonical" href="https://secscan.us/" />
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    { "@type": "Organization", "@id": "https://secscan.us/#organization", "name": "SecScan" },
    { "@type": "WebSite", "@id": "https://secscan.us/#website", "url": "https://secscan.us" },
    { "@type": "WebPage", "@id": "https://secscan.us/#webpage", "url": "https://secscan.us/", "name": "Home" },
    { "@type": "SoftwareApplication", "@id": "https://secscan.us/#app", "name": "SecScan" },
    { "@type": "HowTo", "name": "How to scan" },
    { "@type": "FAQPage", "mainEntity": [] }
  ]
}
</script>
</head><body></body></html>`;

function graphOf(html: string): Record<string, unknown>[] {
  const m = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/i.exec(html);
  if (!m?.[1]) throw new Error("no JSON-LD block");
  return (JSON.parse(m[1]) as { "@graph": Record<string, unknown>[] })["@graph"];
}

describe("structured data per route", () => {
  it("points the WebPage node at the route being served, not the homepage", () => {
    const out = applyPageMeta(SHELL_WITH_LD, metaForPath("/learn")!);
    const page = graphOf(out).find((n) => n["@type"] === "WebPage")!;

    expect(page["url"]).toBe("https://secscan.us/learn");
    expect(page["@id"]).toBe("https://secscan.us/learn#webpage");
    expect(page["name"]).toBe("Security Documentation — SecScan.us");
  });

  it("agrees with the canonical tag on the same page", () => {
    const out = applyPageMeta(SHELL_WITH_LD, metaForPath("/bot")!);
    const canonical = /<link rel="canonical" href="([^"]+)"/.exec(out)?.[1];
    const page = graphOf(out).find((n) => n["@type"] === "WebPage")!;

    expect(page["url"]).toBe(canonical);
  });

  it("builds a breadcrumb trail from home to the page", () => {
    const out = applyPageMeta(SHELL_WITH_LD, metaForPath("/learn")!);
    const page = graphOf(out).find((n) => n["@type"] === "WebPage")!;
    const crumbs = (page["breadcrumb"] as { itemListElement: { name: string; item: string }[] })
      .itemListElement;

    expect(crumbs.map((c) => c.name)).toEqual(["Home", "Security documentation"]);
    expect(crumbs[1]!.item).toBe("https://secscan.us/learn");
  });

  it("keeps the site-wide nodes, which are true on every page", () => {
    const types = graphOf(applyPageMeta(SHELL_WITH_LD, metaForPath("/terms")!)).map((n) => n["@type"]);
    expect(types).toContain("Organization");
    expect(types).toContain("WebSite");
  });

  it("drops the homepage's pitch from pages that are not the homepage", () => {
    // An Offer and a FAQ about pricing do not belong on the privacy policy.
    const types = graphOf(applyPageMeta(SHELL_WITH_LD, metaForPath("/privacy")!)).map((n) => n["@type"]);
    expect(types).not.toContain("FAQPage");
    expect(types).not.toContain("HowTo");
    expect(types).not.toContain("SoftwareApplication");
  });

  it("emits no structured data at all on a noindex page", () => {
    // Marking a page noindex and then describing it in rich detail is a
    // contradiction; the private routes should simply say nothing.
    const out = applyPageMeta(SHELL_WITH_LD, metaForPath("/dashboard")!);
    expect(out).not.toContain("application/ld+json");
  });

  it("serves the page unchanged rather than throwing on malformed JSON-LD", () => {
    const broken = SHELL_WITH_LD.replace('"@context": "https://schema.org",', '"@context": ,,,');
    expect(() => applyPageMeta(broken, metaForPath("/learn")!)).not.toThrow();
    // The head rewrite still has to happen even when the graph cannot be read.
    expect(applyPageMeta(broken, metaForPath("/learn")!)).toContain(
      '<link rel="canonical" href="https://secscan.us/learn" />',
    );
  });

  it("escapes a closing script tag it writes into the graph itself", () => {
    // The title and description are written into the JSON-LD as node values.
    // Serialising "</script>" raw would end the block early and leave the rest
    // of the graph as markup in the document.
    const out = applyPageMeta(SHELL_WITH_LD, {
      path: "/learn",
      title: "</script><img src=x onerror=alert(1)>",
      description: "Also </script> here.",
    });

    expect(out).not.toContain("</script><img");
    // Still exactly one JSON-LD block, still parseable.
    expect(out.match(/application\/ld\+json/g)).toHaveLength(1);
    const page = graphOf(out).find((n) => n["@type"] === "WebPage")!;
    expect(page["name"]).toBe("</script><img src=x onerror=alert(1)>");
  });
});

describe("visible breadcrumbs match the structured data", () => {
  // Google expects BreadcrumbList JSON-LD to describe breadcrumbs the page
  // actually shows. The visible ones live in the frontend layout; this fails
  // if either side is renamed without the other.
  it("names every subpage the same in the layout as in the JSON-LD", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    // The breadcrumb table lives in layout-account-nav.tsx, split out of layout.tsx for size.
    const layout = ["layout.tsx", "layout-account-nav.tsx"]
      .map((f) => readFileSync(resolve(__dirname, "../../../vibescan/src/components", f), "utf8"))
      .join("\n");
    for (const path of ["/learn", "/privacy", "/terms", "/bot", "/about"]) {
      const crumb = metaForPath(path)?.breadcrumb?.at(-1);
      expect(crumb, `${path} has no breadcrumb in pageMeta`).toBeDefined();
      expect(layout).toContain(`"${path}": "${crumb!.name}"`);
    }
  });
});

describe("withRenderedRoot", () => {
  const SHELL_ROOT = '<body><div id="root"></div><script src="/a.js"></script></body>';

  it("fills the empty app container and leaves the rest alone", () => {
    expect(withRenderedRoot(SHELL_ROOT, "<h1>Hi</h1>")).toBe(
      '<body><div id="root"><h1>Hi</h1></div><script src="/a.js"></script></body>',
    );
  });

  it("keeps $ sequences in the markup literal", () => {
    expect(withRenderedRoot(SHELL_ROOT, "<p>$& $1 $$ $'</p>")).toContain("<p>$& $1 $$ $'</p>");
  });

  it("returns the shell unchanged when there is no fragment", () => {
    expect(withRenderedRoot(SHELL_ROOT, undefined)).toBe(SHELL_ROOT);
    expect(withRenderedRoot(SHELL_ROOT, "")).toBe(SHELL_ROOT);
  });

  it("does not touch a shell whose container is not empty", () => {
    const filled = '<div id="root"><p>x</p></div>';
    expect(withRenderedRoot(filled, "<h1>Hi</h1>")).toBe(filled);
  });

  it("names the same pages as the build script that renders them", () => {
    const script = readFileSync(new URL("../../scripts/prerender-public.mjs", import.meta.url), "utf8");
    const block = /const PAGES = \{([^}]*)\}/.exec(script)?.[1] ?? "";
    const pages = Object.fromEntries([...block.matchAll(/"([^"]+)":\s*"([^"]+)"/g)].map((m) => [m[1], m[2]]));
    expect(pages).toEqual(PRERENDERED);
  });
});

describe("TechArticle on the documentation page", () => {
  it("describes /learn as an article by the founder, linked to its page", () => {
    const g = graphOf(applyPageMeta(SHELL_WITH_LD, metaForPath("/learn")!));
    const article = g.find((n) => n["@type"] === "TechArticle")!;

    expect(article["url"]).toBe("https://secscan.us/learn");
    expect(article["author"]).toEqual({ "@id": "https://secscan.us/#founder" });
    expect(article["publisher"]).toEqual({ "@id": "https://secscan.us/#organization" });
    expect(article["isPartOf"]).toEqual({ "@id": "https://secscan.us/learn#webpage" });
    expect(article["dateModified"]).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("is on no other page", () => {
    for (const path of ["/", "/about", "/bot", "/privacy", "/terms"]) {
      const meta = metaForPath(path);
      if (!meta) continue;
      expect(graphOf(applyPageMeta(SHELL_WITH_LD, meta)).map((n) => n["@type"]), path).not.toContain("TechArticle");
    }
  });

  it("carries the date shown on the page as 'last reviewed'", () => {
    const page = readFileSync(new URL("../../../vibescan/src/pages/learn-checks.ts", import.meta.url), "utf8");
    const shown = /LEARN_LAST_REVIEWED = "([^"]+)"/.exec(page)?.[1];
    expect(shown).toBeDefined();
    const iso = new Date(`${shown} 00:00:00 UTC`).toISOString().slice(0, 10);
    expect(metaForPath("/learn")!.article?.dateModified).toBe(iso);
  });
});
