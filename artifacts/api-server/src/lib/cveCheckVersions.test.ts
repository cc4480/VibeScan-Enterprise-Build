import { describe, it, expect } from "vitest";
import { extractVersionedTechnologies } from "./cveCheckVersions.js";

const detect = (html: string) =>
  extractVersionedTechnologies(html, {}).map((d) => `${d.displayName} ${d.version}`);
const page = (head: string, body = "") => `<!doctype html><html><head>${head}</head><body>${body}</body></html>`;

describe("extractVersionedTechnologies — only what the page loads or runs", () => {
  it.each([
    ["a changelog sentence", page("", "<p>We removed our last dependency on jquery-1.12.4 this release.</p>")],
    ["an install snippet shown as escaped text", page("", '<pre><code>&lt;script src="https://code.jquery.com/jquery-1.12.4.min.js"&gt;&lt;/script&gt;</code></pre>')],
    ["a download link to an old release", page("", '<a href="https://code.jquery.com/jquery-1.12.4.min.js">jQuery 1.12.4</a>')],
    ["page-state JSON that carries the prose", page("", '<script id="__NEXT_DATA__" type="application/json">{"post":"Upgrading from jquery-1.12.4"}</script>')],
    ["a commented-out script tag", page('<!-- <script src="/js/jquery-1.12.4.min.js"></script> -->')],
  ])("ignores a version named in %s", (_n, html) => {
    expect(detect(html)).toEqual([]);
  });

  it("ignores a commented-out script whose comment closes past the 150KB scan limit", () => {
    const commented = `<!-- <script src="/js/jquery-1.12.4.min.js"></script>${"x".repeat(200_000)} -->`;
    expect(detect(page(commented))).toEqual([]);
  });

  it("does not read another package whose name ends in the library's name", () => {
    expect(detect(page('<script src="https://unpkg.com/react-bootstrap@2.10.0/dist/react-bootstrap.min.js"></script>'))).toEqual([]);
    expect(detect(page('<script src="https://cdn.jsdelivr.net/npm/isomorphic-dompurify@2.3.0/dist/browser.js"></script>'))).toEqual([]);
    expect(detect(page('<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-moment@1.0.1"></script>'))).toEqual([]);
  });

  it("does not report Bootstrap for a stylesheet alone: its advisories are all in its JavaScript", () => {
    expect(detect(page('<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/css/bootstrap.min.css">'))).toEqual([]);
  });

  it("does not read a WordPress theme's own ?ver= as the library version", () => {
    const theme = page(
      '<link rel="stylesheet" href="/wp-content/themes/acme/css/bootstrap.min.css?ver=1.0.0">' +
      '<script src="/wp-content/themes/acme/js/bootstrap.min.js?ver=1.0.0"></script>' +
      '<script src="/wp-content/themes/acme/js/jquery.min.js?ver=1.0.0"></script>',
    );
    expect(detect(theme)).toEqual([]);
  });

  it("reads WordPress core's bundled jQuery as jQuery, not as the WordPress version", () => {
    expect(detect(page("<script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1' id='jquery-core-js'></script>"))).toEqual(["jQuery 3.7.1"]);
  });
});

describe("extractVersionedTechnologies — real loads are still detected", () => {
  it.each([
    ["a CDN script", '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>', "jQuery 1.12.4"],
    ["an npm CDN script", "<script defer src='https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/js/bootstrap.min.js'></script>", "Bootstrap 3.3.7"],
    ["a CDN stylesheet next to a self-hosted Bootstrap script", '<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"><script src="/assets/bootstrap.bundle.min.js"></script>', "Bootstrap 3.3.7"],
    ["a library banner in an inline script", "<script>/*! jQuery JavaScript Library v1.8.3 */ (function(){})();</script>", "jQuery 1.8.3"],
    ["an import map", '<script type="importmap">{"imports":{"vue":"https://unpkg.com/vue@3.2.0/dist/vue.esm-browser.js"}}</script>', "Vue.js 3.2.0"],
    ["a module preload", '<link rel="modulepreload" href="https://esm.sh/lodash@4.17.15">', "Lodash 4.17.15"],
    ["a generator meta tag", '<meta name="generator" content="WordPress 6.4.2">', "WordPress 6.4.2"],
  ])("detects %s", (_n, head, expected) => {
    expect(detect(page(head))).toContain(expected);
  });
});
