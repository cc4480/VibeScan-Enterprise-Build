import { describe, it, expect } from "vitest";
import { extractInternalLinks, seedCookieIssuesFromRoot, buildHeaderGapVulns } from "./crawler.js";

const BASE = "https://example.com";

describe("extractInternalLinks", () => {
  it("returns empty array for an invalid baseUrl", () => {
    expect(extractInternalLinks(`<a href="/about">`, "not-a-url")).toEqual([]);
  });

  it("returns empty array for empty HTML", () => {
    expect(extractInternalLinks("", BASE)).toEqual([]);
  });

  it("extracts an absolute same-domain href", () => {
    const html = `<a href="https://example.com/about">About</a>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/about");
  });

  it("resolves a root-relative href", () => {
    const html = `<a href="/contact">Contact</a>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/contact");
  });

  it("resolves a relative href", () => {
    const html = `<a href="blog/post-1">Post</a>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/blog/post-1");
  });

  it("excludes off-domain hrefs", () => {
    const html = `<a href="https://evil.com/steal">click</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(0);
  });

  it("excludes javascript: hrefs", () => {
    expect(extractInternalLinks(`<a href="javascript:void(0)">x</a>`, BASE)).toHaveLength(0);
  });

  it("excludes mailto: hrefs", () => {
    expect(extractInternalLinks(`<a href="mailto:foo@bar.com">email</a>`, BASE)).toHaveLength(0);
  });

  it("excludes tel: hrefs", () => {
    expect(extractInternalLinks(`<a href="tel:+15550001234">call</a>`, BASE)).toHaveLength(0);
  });

  it("deduplicates repeated hrefs", () => {
    const html = `<a href="/about">1</a><a href="/about">2</a><a href="/about">3</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(1);
  });

  it("excludes the root path '/'", () => {
    expect(extractInternalLinks(`<a href="/">Home</a>`, BASE)).toHaveLength(0);
  });

  it("excludes the base URL itself", () => {
    const html = `<a href="https://example.com">Home</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(0);
  });

  it("strips query strings when deduplicating", () => {
    const html = `<a href="/products?cat=shoes">1</a><a href="/products">2</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(1);
    expect(extractInternalLinks(html, BASE)[0]).toBe("https://example.com/products");
  });

  it("strips fragment anchors when deduplicating", () => {
    const html = `<a href="/products#top">1</a><a href="/products">2</a>`;
    expect(extractInternalLinks(html, BASE)).toHaveLength(1);
  });

  it("excludes dangerous path: /logout", () => {
    expect(extractInternalLinks(`<a href="/logout">Logout</a>`, BASE)).toHaveLength(0);
  });

  it("excludes dangerous path: /delete", () => {
    expect(extractInternalLinks(`<a href="/delete-account">Delete</a>`, BASE)).toHaveLength(0);
  });

  it("excludes dangerous path: /signout", () => {
    expect(extractInternalLinks(`<a href="/signout">Sign out</a>`, BASE)).toHaveLength(0);
  });

  it("excludes dangerous path: /reset", () => {
    expect(extractInternalLinks(`<a href="/reset-password">Reset</a>`, BASE)).toHaveLength(0);
  });

  it("extracts form action pointing to a .php page", () => {
    const html = `<form action="/submit.php"><input type="submit"/></form>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/submit.php");
  });

  it("extracts img src pointing to an .asp page", () => {
    const html = `<img src="/image-handler.asp"/>`;
    expect(extractInternalLinks(html, BASE)).toContain("https://example.com/image-handler.asp");
  });

  it("handles multiple valid links at once", () => {
    const html = `
      <a href="/about">About</a>
      <a href="/pricing">Pricing</a>
      <a href="/blog">Blog</a>
      <a href="https://evil.com">Evil</a>
    `;
    const result = extractInternalLinks(html, BASE);
    expect(result).toHaveLength(3);
    expect(result).toContain("https://example.com/about");
    expect(result).toContain("https://example.com/pricing");
    expect(result).toContain("https://example.com/blog");
  });
});

describe("seedCookieIssuesFromRoot", () => {
  // The root page's cookies are analysed in scanner.ts, the inner pages' in the
  // crawler. Without seeding, a cookie set on BOTH was reported twice — once as
  // "Missing Secure Flag" and again as "Missing Secure Flag on Inner Page".
  // Seen on google.com with NID, where both findings were factually correct,
  // which is exactly what makes the duplicate corrosive.
  it("records defects the root already reported so the crawl does not repeat them", () => {
    const seen = seedCookieIssuesFromRoot(["NID=abc; expires=Tue, 09-Mar-2027 08:52:06 GMT; path=/; domain=.google.com; HttpOnly"]);
    expect(seen.has("secure::NID")).toBe(true);   // no Secure -> root reported it
    expect(seen.has("httponly::NID")).toBe(false); // HttpOnly IS set -> nothing to report
  });

  it("does not seed defects the root did not have, so inner pages stay catchable", () => {
    // A properly flagged cookie on the root must not mask the SAME cookie being
    // set badly on an inner page.
    const seen = seedCookieIssuesFromRoot(["sid=1; Secure; HttpOnly"]);
    expect(seen.size).toBe(0);
  });

  it("takes cookies already split, so a comma inside expires cannot shear them", () => {
    // The list arrives pre-split by getSetCookie(), so the comma inside expires
    // is just data — the shearing that caused the NID false positive cannot occur.
    const seen = seedCookieIssuesFromRoot(["a=1; expires=Tue, 09-Mar-2027 08:52:06 GMT; path=/", "b=2; Secure"]);
    expect(seen.has("secure::a")).toBe(true);
    expect(seen.has("secure::b")).toBe(false);
  });

  it("ignores infrastructure cookies the site operator cannot change", () => {
    const seen = seedCookieIssuesFromRoot(["__cf_bm=x; path=/"]);
    expect(seen.has("secure::__cf_bm")).toBe(false);
  });

  it("is empty when the response sets no cookies", () => {
    expect(seedCookieIssuesFromRoot([]).size).toBe(0);
  });
});

describe("header-gap evidence keeps the query string", () => {
  // Found by the 2026-09-10 re-scan. paypal.com links every internal page as
  // "…/giving?locale.x=en_US". That URL answers with a CSP carrying no
  // frame-ancestors; the bare "…/giving" answers with a DIFFERENT CSP that has
  // it. The crawl fetched the linked form and was right — but the evidence
  // printed only `new URL(p).pathname`, so verifying the finding the way the
  // false-positive audit requires led straight to the wrong URL and made a true
  // finding look false.
  const root = { hsts: true, csp: true, xfo: true, xcto: true, rp: true };

  it("prints the query that produced the observation", () => {
    const gap = new Map([
      ["xfo", ["https://www.paypal.com/us/digital-wallet/send-receive-money/giving?locale.x=en_US"]],
    ] as const);
    const [v] = buildHeaderGapVulns(root, gap as never, new Set());
    expect(v!.evidence).toContain("?locale.x=en_US");
    expect(v!.evidence).toContain("/us/digital-wallet/send-receive-money/giving");
  });

  it("still labels how the route was reached", () => {
    const probed = "https://example.com/dashboard?next=%2Fhome";
    const gap = new Map([["csp", [probed]]] as const);
    const [v] = buildHeaderGapVulns(root, gap as never, new Set([probed]));
    expect(v!.evidence).toContain("?next=%2Fhome");
    expect(v!.evidence).toContain("(probed)");
  });

  it("leaves a query-less route unchanged", () => {
    const gap = new Map([["rp", ["https://example.com/about"]]] as const);
    const [v] = buildHeaderGapVulns(root, gap as never, new Set());
    expect(v!.evidence).toContain("  • /about (crawled)");
    expect(v!.evidence).not.toContain("?");
  });

  it("says nothing when the root lacked the header itself", () => {
    // A gap is only a gap against a root that had it — otherwise it is the
    // site-wide "missing header" finding, reported elsewhere.
    const gap = new Map([["xfo", ["https://example.com/a?b=1"]]] as const);
    expect(buildHeaderGapVulns({ ...root, xfo: false }, gap as never, new Set())).toEqual([]);
  });
});
