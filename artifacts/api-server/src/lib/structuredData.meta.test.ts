import { PAGE, goodHtml, names } from "./structuredData.testkit";
import { describe, it, expect } from "vitest";
import { extractPageMetadata, structuredDataFindings } from "./structuredData.js";

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

  it("does not flag prose, versions or file names that merely look internal", () => {
    // A tech-blog article: localhost in a sentence, a macOS version, foo.test / settings.local file names.
    const html = goodHtml(`<script type="application/ld+json">
      {"@context":"https://schema.org","@type":"TechArticle","url":"https://blog.example.com/post",
       "headline":"Run the dev server","description":"Open http://localhost:3000, then rename foo.test and edit settings.local",
       "softwareVersion":"10.15.7.1","operatingSystem":"macOS 10.15.7.1"}
    </script>`);
    expect(names(html)).not.toContain("Internal Hostname Exposed in Structured Data");
  });

  it("flags an internal host in a nested sameAs or image URL", () => {
    const html = goodHtml(`<script type="application/ld+json">
      {"@context":"https://schema.org","@type":"Organization","sameAs":["https://twitter.com/x","http://intranet.corp/x"],
       "image":{"@type":"ImageObject","url":"http://192.168.1.20/a.png"}}
    </script>`);
    const leak = structuredDataFindings(PAGE, html).find((v) => v.name === "Internal Hostname Exposed in Structured Data");
    expect(leak?.evidence).toContain("intranet.corp");
    expect(leak?.evidence).toContain("192.168.1.20");
  });

  it("does not walk into a block that failed to parse", () => {
    const html = goodHtml(`<script type="application/ld+json">{"url":"http://10.0.0.1",}</script>`);
    const f = names(html);
    expect(f).toContain("Malformed JSON-LD Structured Data");
    expect(f).not.toContain("Internal Hostname Exposed in Structured Data");
  });
});
