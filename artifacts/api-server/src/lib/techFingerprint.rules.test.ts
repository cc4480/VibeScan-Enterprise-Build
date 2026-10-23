import { describe, it, expect } from "vitest";
import { detectTechnologies } from "./techFingerprint.js";

// ── Regression: false positives found by scanning secscan.info ──────────────
//
// A static Astro site was reported as Next.js + Tailwind + Bootstrap, and its
// documentation pages as Lovable + Bolt.new. Every one came from matching a
// generic class name or a word in prose. Technologies feed CVE matching, so a
// phantom framework produces alerts for advisories that cannot apply.

describe("detectTechnologies — does not fire on prose or generic classes", () => {
  it("ignores __NEXT_DATA__ mentioned in text", () =>
    expect(
      detectTechnologies({}, "<p>Next.js serialises props into __NEXT_DATA__ in the page.</p>"),
    ).not.toContain("Next.js"));

  it("ignores a semantic grid class", () =>
    expect(detectTechnologies({}, '<div class="grid"><div class="card">x</div></div>')).not.toContain(
      "Tailwind CSS",
    ));

  it("ignores a lone utility-shaped class", () =>
    expect(detectTechnologies({}, '<div class="text-sm">x</div>')).not.toContain("Tailwind CSS"));

  it("ignores anchor ids that look like margin utilities", () =>
    expect(
      detectTechnologies({}, '<section id="m-scanner"></section><a href="#m-probes">x</a>'),
    ).not.toContain("Tailwind CSS"));

  it("ignores hyphenated class names ending in row", () =>
    expect(detectTechnologies({}, '<div class="cta-row"><div class="row">x</div></div>')).not.toContain(
      "Bootstrap",
    ));

  it("ignores a hand-rolled btn btn-primary", () =>
    expect(detectTechnologies({}, '<a class="btn btn-primary">x</a>')).not.toContain("Bootstrap"));

  it("ignores a container class", () =>
    expect(detectTechnologies({}, '<div class="container">x</div>')).not.toContain("Bootstrap"));

  it("ignores the word columns", () =>
    expect(detectTechnologies({}, '<div class="columns">x</div>')).not.toContain("Bulma"));

  it("ignores AI-builder hostnames written in prose", () => {
    const prose = "<p>Apps on lovable.app, bolt.new or .stackblitz.io get targeted checks.</p>";
    expect(detectTechnologies({}, prose)).not.toContain("Lovable");
    expect(detectTechnologies({}, prose)).not.toContain("Bolt.new");
  });
});

describe("detectTechnologies — still detects the real thing", () => {
  it("detects Tailwind from a cluster of real utilities", () =>
    expect(
      detectTechnologies({}, '<div class="flex items-center gap-4 px-6 py-3 text-sm bg-white rounded-lg">x</div>'),
    ).toContain("Tailwind CSS"));

  it("detects Tailwind from palette colours", () =>
    expect(
      detectTechnologies({}, '<div class="bg-slate-800 text-white border-gray-200 rounded-lg shadow-md">x</div>'),
    ).toContain("Tailwind CSS"));

  it("detects Tailwind from the CDN script", () =>
    expect(detectTechnologies({}, '<script src="https://cdn.tailwindcss.com"></script>')).toContain(
      "Tailwind CSS",
    ));

  it("detects Bootstrap from its stylesheet", () =>
    expect(detectTechnologies({}, '<link href="/css/bootstrap.min.css" rel="stylesheet">')).toContain(
      "Bootstrap",
    ));

  it("detects Bootstrap from a data-bs- attribute", () =>
    expect(detectTechnologies({}, '<button data-bs-toggle="modal">x</button>')).toContain("Bootstrap"));

  it("detects Bootstrap from a breakpoint grid class", () =>
    expect(detectTechnologies({}, '<div class="col-md-6">x</div>')).toContain("Bootstrap"));

  it("detects Next.js from the __NEXT_DATA__ script element", () =>
    expect(
      detectTechnologies({}, '<script id="__NEXT_DATA__" type="application/json">{}</script>'),
    ).toContain("Next.js"));

  it("detects Next.js from a _next/static asset", () =>
    expect(detectTechnologies({}, '<script src="/_next/static/chunks/main.js"></script>')).toContain(
      "Next.js",
    ));

  it("detects Astro from the generator meta", () =>
    expect(detectTechnologies({}, '<meta name="generator" content="Astro v5.18.2">')).toContain("Astro"));

  it("detects Astro from an island", () =>
    expect(detectTechnologies({}, "<astro-island uid=\"x\"></astro-island>")).toContain("Astro"));

  it("detects Lovable from a real asset URL", () =>
    expect(detectTechnologies({}, '<img src="https://lovable-uploads.lovable.app/x.png">')).toContain(
      "Lovable",
    ));

  it("detects Bolt.new from a real script URL", () =>
    expect(detectTechnologies({}, '<script src="https://bolt.new/app.js"></script>')).toContain(
      "Bolt.new",
    ));

  it("detects Bulma from a real column class", () =>
    expect(detectTechnologies({}, '<div class="column is-half">x</div>')).toContain("Bulma"));
});

describe("detectTechnologies — JS libraries need the library, not its name", () => {
  it.each([
    ["jQuery", `<script src="/js/jquery-3.7.1.min.js"></script>`],
    ["jQuery", `<script>jQuery.fn.extend({})</script>`],
    ["Lodash", `<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>`],
    ["Alpine.js", `<div x-data="{ open: false }"></div>`],
    ["Alpine.js", `<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>`],
    ["HTMX", `<button hx-post="/clicked">Go</button>`],
    ["HTMX", `<script src="https://unpkg.com/htmx.org@1.9.10"></script>`],
  ])("detects %s from %s", (tech, html) => expect(detectTechnologies({}, html)).toContain(tech));

  it.each([
    ["jQuery", `<p>We moved off jquery-3 last year; jQuery.fn is gone.</p>`],
    ["Lodash", `<p>Check _.version and lodash.min in your bundle.</p>`],
    ["Alpine.js", `<pre>Add x-data= and x-show= to your markup</pre>`],
    ["HTMX", `<p>See htmx.org: use hx-get and hx-post attributes.</p>`],
  ])("does not tag %s from prose", (tech, html) => expect(detectTechnologies({}, html)).not.toContain(tech));
});

// Rules checked against webappanalyzer (2026-10-02): a header or tag its data supports, not a phrase in prose.
describe("detectTechnologies — rules aligned with webappanalyzer", () => {
  it("x-amz-request-id is AWS, not CloudFront; x-amz-cf-id is CloudFront", () => {
    const s3 = detectTechnologies({ "x-amz-request-id": "ABC" }, "");
    expect(s3).toContain("AWS");
    expect(s3).not.toContain("AWS CloudFront");
    expect(detectTechnologies({ "x-amz-cf-id": "abc" }, "")).toContain("AWS CloudFront");
  });

  it("does not call prose about WordPress, Angular, Joomla or GTM a detection", () => {
    const prose = "<p>Upload to wp-content, then add ng-app and angular.js, /media/jui/ and googletagmanager.com/gtm.js to the page.</p>";
    const found = detectTechnologies({}, prose);
    for (const t of ["WordPress", "Angular", "Joomla", "Google Tag Manager"]) expect(found).not.toContain(t);
  });

  it("detects them from the asset or attribute they actually emit", () => {
    expect(detectTechnologies({}, `<script src="/wp-includes/js/jquery.js"></script>`)).toContain("WordPress");
    expect(detectTechnologies({}, `<div ng-app="x"></div>`)).toContain("Angular");
    expect(detectTechnologies({}, `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-X"></script>`)).toContain("Google Tag Manager");
  });

  it("anchors the X-Powered-By matches", () => {
    expect(detectTechnologies({ "x-powered-by": "Express" }, "")).toContain("Express.js");
    expect(detectTechnologies({ "x-powered-by": "Unexpressed" }, "")).not.toContain("Express.js");
  });

  it("names Replit, Railway, Netlify and Base44 from the signals webappanalyzer lists", () => {
    expect(detectTechnologies({ "replit-cluster": "global" }, "")).toContain("Replit");
    expect(detectTechnologies({ server: "railway" }, "")).toContain("Railway");
    expect(detectTechnologies({ "x-nf-request-id": "01H" }, "")).toContain("Netlify");
    expect(detectTechnologies({}, `<meta name="apple-mobile-web-app-title" content="base44">`)).toContain("Base44");
  });
});
