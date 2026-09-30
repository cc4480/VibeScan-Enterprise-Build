import { structuredDataFindings } from "./structuredData.js";

export const PAGE = "https://www.example.com/";

/** A document with everything present and correct, so tests can remove one thing at a time. */
export function goodHtml(extra = ""): string {
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

export function names(html: string, url = PAGE): string[] {
  return structuredDataFindings(url, html).map((f) => f.name);
}

// ── extraction ─────────────────────────────────────────────────────────────
