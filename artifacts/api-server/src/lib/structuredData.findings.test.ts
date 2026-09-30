import { PAGE, goodHtml, names } from "./structuredData.testkit";
import { describe, it, expect } from "vitest";
import { structuredDataFindings } from "./structuredData.js";

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
