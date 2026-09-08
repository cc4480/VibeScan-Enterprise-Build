import { describe, it, expect } from "vitest";
import { extractPageMetadata, structuredDataFindings } from "./structuredData.js";

const PAGE = "https://www.example.com/";

/** A document with everything present and correct, so tests can remove one thing at a time. */
function goodHtml(extra = ""): string {
  return `<!doctype html><html><head>
    <title>Example</title>
    <link rel="canonical" href="https://www.example.com/">
    <meta property="og:title" content="Example">
    <meta property="og:description" content="An example page">
    <meta property="og:image" content="https://www.example.com/card.png">
    <meta property="og:type" content="website">
    <meta name="twitter:card" content="summary_large_image">
    <script type="application/ld+json">
      {"@context":"https://schema.org","@type":"Organization","name":"Example"}
    </script>
    ${extra}
  </head><body></body></html>`;
}

function names(html: string, url = PAGE): string[] {
  return structuredDataFindings(url, html).map((f) => f.name);
}

// ── extraction ─────────────────────────────────────────────────────────────

describe("extractPageMetadata", () => {
  it("reads property=, name=, single-quoted and unquoted attributes", () => {
    // Real documents use all four spellings. A reader that only handles
    // double-quoted property= sees nothing on the sites that need it most.
    const md = extractPageMetadata(`
      <meta property="og:title" content="Double">
      <meta name='twitter:card' content='summary'>
      <meta name=description content=Unquoted>
    `);
    expect(md.meta.get("og:title")).toBe("Double");
    expect(md.meta.get("twitter:card")).toBe("summary");
    expect(md.meta.get("description")).toBe("Unquoted");
  });

  it("decodes entities in attribute values and the title", () => {
    const md = extractPageMetadata(
      `<title>Tom &amp; Jerry</title><meta property="og:title" content="A &quot;quoted&quot; name">`,
    );
    expect(md.title).toBe("Tom & Jerry");
    expect(md.meta.get("og:title")).toBe('A "quoted" name');
  });

  it("keeps the first occurrence when a tag is repeated", () => {
    const md = extractPageMetadata(
      `<meta property="og:title" content="First"><meta property="og:title" content="Second">`,
    );
    expect(md.meta.get("og:title")).toBe("First");
  });

  it("parses JSON-LD and records a parse error without throwing", () => {
    const md = extractPageMetadata(`
      <script type="application/ld+json">{"@type":"Organization"}</script>
      <script type="application/ld+json">{"@type":"Product",}</script>
    `);
    expect(md.jsonLd).toHaveLength(2);
    expect(md.jsonLd[0].parseError).toBeNull();
    expect(md.jsonLd[1].parseError).toBeTruthy();
  });

  it("ignores scripts that are not ld+json", () => {
    const md = extractPageMetadata(
      `<script type="text/javascript">var x = {"@type":"Organization"};</script>`,
    );
    expect(md.jsonLd).toHaveLength(0);
  });

  it("finds rel=canonical regardless of attribute order", () => {
    const md = extractPageMetadata(`<link href="https://a.example/x" rel="canonical">`);
    expect(md.canonical).toBe("https://a.example/x");
  });
});

// ── the well-formed page must be silent ────────────────────────────────────

describe("structuredDataFindings on a correct page", () => {
  it("reports nothing at all", () => {
    expect(structuredDataFindings(PAGE, goodHtml())).toEqual([]);
  });

  it("never emits a finding that would move the security grade", () => {
    // The whole design rests on this: presentation findings are INFO, which
    // computeRiskScore weights at 0. If one of these ever ships as low or
    // above, a site with no og:image starts grading as less secure than one
    // with it, and the grade stops meaning security.
    const html = `<!doctype html><html><head><title>Bare</title></head><body></body></html>`;
    const presentation = structuredDataFindings(PAGE, html)
      .filter((f) => f.category === "Structured Data");
    expect(presentation.length).toBeGreaterThan(0);
    for (const f of presentation) expect(f.severity).toBe("info");
  });
});

// ── security-relevant findings ─────────────────────────────────────────────

describe("internal host disclosure", () => {
  it("flags a private address buried deep in structured data", () => {
    const html = goodHtml(`<script type="application/ld+json">
      {"@context":"https://schema.org","@type":"WebSite",
       "publisher":{"@type":"Organization","logo":{"url":"http://10.0.4.17/assets/logo.png"}}}
    </script>`);
    const f = structuredDataFindings(PAGE, html);
    const leak = f.find((v) => v.name === "Internal Hostname Exposed in Structured Data");
    expect(leak?.severity).toBe("low");
    expect(leak?.evidence).toContain("10.0.4.17");
  });

  it("flags .internal and localhost hostnames", () => {
    for (const host of ["https://cms.internal/api", "http://localhost:3000/img.png"]) {
      const html = goodHtml(
        `<script type="application/ld+json">{"@context":"https://schema.org","@type":"Thing","url":"${host}"}</script>`,
      );
      expect(names(html)).toContain("Internal Hostname Exposed in Structured Data");
    }
  });

  it("does not flag public hostnames that merely contain the words", () => {
    // "local" inside a public domain is not a private host. This is the
    // obvious way to make the check noisy on real sites.
    const html = goodHtml(`<script type="application/ld+json">
      {"@context":"https://schema.org","@type":"Thing",
       "url":"https://local-news.example.com/","name":"Corporate Test Lab"}
    </script>`);
    expect(names(html)).not.toContain("Internal Hostname Exposed in Structured Data");
  });

  it("does not flag a public IP address", () => {
    const html = goodHtml(
      `<script type="application/ld+json">{"@context":"https://schema.org","@type":"Thing","url":"https://8.8.8.8/x"}</script>`,
    );
    expect(names(html)).not.toContain("Internal Hostname Exposed in Structured Data");
  });

  it("does not walk into a block that failed to parse", () => {
    const html = goodHtml(`<script type="application/ld+json">{"url":"http://10.0.0.1",}</script>`);
    const f = names(html);
    expect(f).toContain("Malformed JSON-LD Structured Data");
    expect(f).not.toContain("Internal Hostname Exposed in Structured Data");
  });
});

describe("social preview assets over http", () => {
  it("flags an http og:image on an https page", () => {
    const html = goodHtml().replace(
      'content="https://www.example.com/card.png"',
      'content="http://www.example.com/card.png"',
    );
    const f = structuredDataFindings(PAGE, html);
    const mixed = f.find((v) => v.name === "Social Preview Asset Referenced Over HTTP");
    expect(mixed?.severity).toBe("low");
  });

  it("says nothing when the page itself is http", () => {
    // An http page referencing http assets is not a downgrade; the page is the
    // problem, and other checks already report that.
    const html = goodHtml().replace(
      'content="https://www.example.com/card.png"',
      'content="http://www.example.com/card.png"',
    );
    expect(names(html, "http://www.example.com/")).not.toContain(
      "Social Preview Asset Referenced Over HTTP",
    );
  });

  it("says nothing about a protocol-relative URL", () => {
    const html = goodHtml().replace(
      'content="https://www.example.com/card.png"',
      'content="//cdn.example.com/card.png"',
    );
    expect(names(html)).not.toContain("Social Preview Asset Referenced Over HTTP");
  });
});

describe("canonical URL", () => {
  it("flags a canonical pointing at an unrelated domain", () => {
    const html = goodHtml().replace(
      'href="https://www.example.com/"',
      'href="https://pharma-spam.test/cheap"',
    );
    const f = structuredDataFindings(PAGE, html);
    const c = f.find((v) => v.name === "Canonical URL Points to an External Domain");
    expect(c?.severity).toBe("low");
    expect(c?.description).toContain("pharma-spam.test");
  });

  it("accepts apex/www and subdomain differences", () => {
    // www.example.com canonicalising to example.com is the single most common
    // correct configuration there is.
    for (const [page, canon] of [
      ["https://www.example.com/", "https://example.com/"],
      ["https://example.com/", "https://www.example.com/"],
      ["https://blog.example.com/p", "https://example.com/p"],
    ] as const) {
      const html = goodHtml().replace('href="https://www.example.com/"', `href="${canon}"`);
      expect(names(html, page)).not.toContain("Canonical URL Points to an External Domain");
    }
  });

  it("accepts a relative canonical", () => {
    const html = goodHtml().replace('href="https://www.example.com/"', 'href="/index.html"');
    expect(names(html)).not.toContain("Canonical URL Points to an External Domain");
  });

  it("does not flag a multi-part TLD as external", () => {
    // The reason this compares by suffix instead of computing a registrable
    // domain: getting co.uk wrong fires a false positive on precisely the
    // international sites least equipped to dismiss it.
    const html = goodHtml().replace(
      'href="https://www.example.com/"',
      'href="https://example.co.uk/"',
    );
    expect(names(html, "https://www.example.co.uk/")).not.toContain(
      "Canonical URL Points to an External Domain",
    );
  });
});

// ── presentation findings ──────────────────────────────────────────────────

describe("structured data quality", () => {
  it("reports malformed JSON-LD", () => {
    const html = goodHtml(`<script type="application/ld+json">{"@type":"Product",}</script>`);
    expect(names(html)).toContain("Malformed JSON-LD Structured Data");
  });

  it("reports a block missing @context or @type", () => {
    const html = `<html><head><meta property="og:title" content="t"><meta property="og:description" content="d"><meta property="og:image" content="https://x.example/i.png"><meta name="twitter:card" content="summary">
      <script type="application/ld+json">{"name":"No typing here"}</script></head></html>`;
    expect(names(html)).toContain("Structured Data Missing @context or @type");
  });

  it("accepts an @graph wrapper, which carries typing on its nodes", () => {
    const html = goodHtml(`<script type="application/ld+json">
      {"@context":"https://schema.org","@graph":[{"@type":"WebSite","name":"x"}]}
    </script>`);
    expect(names(html)).not.toContain("Structured Data Missing @context or @type");
  });

  it("reports a page with no structured data at all", () => {
    const html = `<html><head><title>Nothing</title></head><body></body></html>`;
    expect(names(html)).toContain("No Structured Data Found");
  });

  it("lists exactly which Open Graph tags are missing", () => {
    const html = goodHtml().replace(/<meta property="og:image"[^>]*>/, "");
    const f = structuredDataFindings(PAGE, html);
    const og = f.find((v) => v.name === "Incomplete Open Graph Metadata");
    expect(og?.description).toContain("og:image");
    expect(og?.description).not.toContain("og:title");
  });

  it("mentions twitter:card only when Open Graph is otherwise present", () => {
    const withOg = goodHtml().replace(/<meta name="twitter:card"[^>]*>/, "");
    expect(names(withOg)).toContain("Twitter Card Metadata Absent");

    const bare = `<html><head><title>x</title></head></html>`;
    expect(names(bare)).not.toContain("Twitter Card Metadata Absent");
  });

  it("reports a noindex robots tag", () => {
    const html = goodHtml(`<meta name="robots" content="noindex, nofollow">`);
    expect(names(html)).toContain("Page Excluded From Search Indexes");
  });

  it("does not read noindex out of an unrelated robots directive", () => {
    const html = goodHtml(`<meta name="robots" content="max-image-preview:large, noarchive">`);
    expect(names(html)).not.toContain("Page Excluded From Search Indexes");
  });
});

describe("robustness", () => {
  it("returns nothing for an unparseable page URL rather than throwing", () => {
    expect(structuredDataFindings("not a url", goodHtml())).toEqual([]);
  });

  it("handles an empty document", () => {
    expect(() => structuredDataFindings(PAGE, "")).not.toThrow();
  });

  it("does not stall on a large document", () => {
    const html = goodHtml() + "<p>filler</p>".repeat(80_000);
    const t = Date.now();
    structuredDataFindings(PAGE, html);
    expect(Date.now() - t).toBeLessThan(2000);
  });
});

// ── WAF interception ───────────────────────────────────────────────────────

describe("challenge pages", () => {
  const CHALLENGE = `<!DOCTYPE html><html><head><title>Just a moment...</title>
    <meta name="robots" content="noindex,nofollow">
    <link rel="canonical" href="https://cloudflare-spam.test/">
    </head><body><script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script>
    </body></html>`;

  it("reports nothing when the edge answered instead of the site", () => {
    // Every statement this module could make about the interstitial would be
    // attributed to the customer's domain: no Open Graph, no structured data,
    // noindex, and a canonical pointing somewhere else entirely.
    expect(structuredDataFindings(PAGE, CHALLENGE, { status: 403 })).toEqual([]);
  });

  it("still reports normally when the document is the real site", () => {
    expect(structuredDataFindings(PAGE, goodHtml(), { status: 200 })).toEqual([]);
    const bare = `<html><head><title>Real page</title></head><body>${"<p>x</p>".repeat(300)}</body></html>`;
    expect(structuredDataFindings(PAGE, bare, { status: 200 }).length).toBeGreaterThan(0);
  });

  it("assumes a real page when status and headers are not supplied", () => {
    // The scanner always passes them; other callers must not silently lose
    // findings by omitting them.
    const bare = `<html><head><title>Real page</title></head><body>${"<p>x</p>".repeat(300)}</body></html>`;
    expect(structuredDataFindings(PAGE, bare).length).toBeGreaterThan(0);
  });
});
