import { describe, it, expect } from "vitest";

import { expectsIntegrity, isDynamicByDesign, isFirstParty } from "./sriPolicy";
import { checkSRI } from "./probes";

const url = (u: string) => new URL(u);

describe("isFirstParty", () => {
  it.each([
    ["www.example.com", "www.example.com"],
    ["www.example.com", "example.com"],
    ["example.com", "www.example.com"],
    ["www.example.com", "static.example.com"],
    ["www.example.com", "cdn.assets.example.com"],
    ["www.example.co.uk", "static.example.co.uk"],
    ["shop.example.com.au", "cdn.example.com.au"],
    ["www.dropbox.com", "cfl.dropboxstatic.com"],
  ])("%s and %s are the same site", (page, res) => {
    expect(isFirstParty(page, res)).toBe(true);
  });

  it.each([
    ["www.example.com", "cdn.jsdelivr.net"],
    ["www.example.com", "example.org"],
    ["www.example.com", "example.com.evil.net"],
    ["www.example.com", "notexample.com"],
    ["www.example.co.uk", "www.other.co.uk"],
    ["a.com.au", "b.com.au"],
    ["www.example.com", "com"],
    ["www.example.com", ""],
    ["www.example.com", "cfl.dropboxstatic.com"],
  ])("%s and %s are strangers", (page, res) => {
    expect(isFirstParty(page, res)).toBe(false);
  });

  it("ignores case and a trailing dot", () => {
    expect(isFirstParty("WWW.Example.COM.", "static.example.com")).toBe(true);
  });
});

describe("isDynamicByDesign", () => {
  it("knows the scripts a provider updates in place", () => {
    for (const u of [
      "https://www.googletagmanager.com/gtm.js?id=GTM-X",
      "https://js.stripe.com/v3/",
      "https://www.google.com/recaptcha/api.js",
      "https://www.gstatic.com/recaptcha/releases/x/recaptcha__en.js",
      "https://fonts.googleapis.com/css2?family=Inter",
      "https://connect.facebook.net/en_US/fbevents.js",
      "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js",
      "https://transcend-cdn.com/cm/abc/airgap.js",
      "https://ct.captcha-delivery.com/c.js",
      "https://de5282c3ca0c.edge.sdk.awswaf.com/de5282c3ca0c/526cf06acb0d/challenge.js",
    ]) expect(isDynamicByDesign(url(u)), u).toBe(true);
    expect(isDynamicByDesign(url("https://sdk.awswaf.com.evil.net/x.js"))).toBe(false);
    expect(isDynamicByDesign(url("https://notsdk.awswaf.com/x.js"))).toBe(false);
  });

  it("does not exempt a version-pinned library on a shared CDN, where SRI is the right thing", () => {
    for (const u of ["https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js", "https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/react.min.js", "https://unpkg.com/lodash@4/lodash.js"]) {
      expect(isDynamicByDesign(url(u)), u).toBe(false);
    }
  });

  it("scopes the path rules: the rest of google.com is not exempt", () => {
    expect(isDynamicByDesign(url("https://www.google.com/some/other.js"))).toBe(false);
  });
});

describe("expectsIntegrity", () => {
  it("expects it for a genuine third-party library, and not for the site's own CDN or a dynamic provider", () => {
    expect(expectsIntegrity("www.example.com", url("https://cdn.jsdelivr.net/npm/x@1/x.js"))).toBe(true);
    expect(expectsIntegrity("www.example.com", url("https://static.example.com/app.js"))).toBe(false);
    expect(expectsIntegrity("www.example.com", url("https://js.stripe.com/v3/"))).toBe(false);
  });
});

describe("checkSRI, end to end on real-world page shapes", () => {
  const page = "https://www.example.com/";
  const found = async (html: string) => (await checkSRI(html, page)).flatMap((v) => (v.evidence ?? "").split("\n"));

  it("stays silent on a page that loads only its own CDN and providers that forbid SRI", async () => {
    const html = `<html><head>
      <link rel="stylesheet" href="https://static.example.com/site.css">
      <script src="https://cdn.example.com/app.js"></script>
      <script src="https://www.googletagmanager.com/gtm.js?id=GTM-1"></script>
      <script src="https://js.stripe.com/v3/"></script>
      <script src="https://www.google.com/recaptcha/api.js"></script></head></html>`;
    expect(await checkSRI(html, page)).toEqual([]);
  });

  it("still flags a version-pinned third-party library without integrity, and names only that one", async () => {
    const html = `<script src="https://static.example.com/a.js"></script>
      <script src="https://js.stripe.com/v3/"></script>
      <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>`;
    const lines = await found(html);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("cdn.jsdelivr.net");
  });

  it("does not flag a third-party script that already carries integrity", async () => {
    const html = `<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js" integrity="sha384-abc" crossorigin="anonymous"></script>`;
    expect(await checkSRI(html, page)).toEqual([]);
  });

  it("still leaves a content-hashed file alone, as before", async () => {
    expect(await checkSRI(`<script src="https://cdn.other.net/chunk.a1b2c3d4e5f6a7b8c9.js"></script>`, page)).toEqual([]);
  });
});

/**
 * Found by the 2026-09-30 sweep: zoom.us redirects to www.zoom.com but keeps its assets on
 * st1.zoom.us. Judged against the final host alone, Zoom's own CDN was reported as a third party.
 */
describe("the address the user asked for counts as first-party after a redirect", () => {
  const finalPage = "https://www.zoom.com/";
  const html = `<script src="https://st1.zoom.us/homepage/main.js"></script>
    <script src="https://cdn.bc0a.com/autopilot/sdk.js"></script>`;

  it("does not report the requested domain's own CDN, and still reports a real third party", async () => {
    const [v] = await checkSRI(html, finalPage, "https://zoom.us");
    const lines = (v?.evidence ?? "").split("\n");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("cdn.bc0a.com");
    expect(v!.evidence).not.toContain("st1.zoom.us");
  });

  it("without the requested address the old behaviour is unchanged (both are strangers)", async () => {
    const [v] = await checkSRI(html, finalPage);
    expect(v!.evidence).toContain("st1.zoom.us");
  });

  it("expectsIntegrity honours the extra first-party host but not a lookalike", () => {
    expect(expectsIntegrity("www.zoom.com", url("https://st1.zoom.us/a.js"), ["zoom.us"])).toBe(false);
    expect(expectsIntegrity("www.zoom.com", url("https://zoom.us.evil.example/a.js"), ["zoom.us"])).toBe(true);
    expect(expectsIntegrity("www.zoom.com", url("https://cdn.bc0a.com/a.js"), ["zoom.us"])).toBe(true);
  });
});

describe("vendor-updated tags get advice that can be followed", async () => {
  const { checkSRI } = await import("./probesSri.js");
  const page = (...srcs: string[]) => srcs.map((s) => `<script src="${s}"></script>`).join("");

  it("still reports the finding, but does not tell the site to pin a tag the vendor edits in place", async () => {
    const [v] = await checkSRI(page("https://cdn.bizible.com/scripts/bizible.js", "https://munchkin.marketo.net/munchkin.js"), "https://www.example.com/");
    expect(v!.name).toBe("External Resources Missing Subresource Integrity (SRI)");
    expect(v!.evidence).toContain("[vendor-updated tag]");
    expect(v!.solution).toContain("self-host a pinned copy");
    expect(v!.solution).not.toContain("openssl");
  });

  it("gives the pinning advice for ordinary CDN files, and both when mixed", async () => {
    const [a] = await checkSRI(page("https://cdn.example.net/lib.js"), "https://www.example.com/");
    expect(a!.solution).toContain("openssl");
    expect(a!.evidence).not.toContain("vendor-updated");
    const [b] = await checkSRI(page("https://cdn.example.net/lib.js", "https://tag.clearbit.com/x.js"), "https://www.example.com/");
    expect(b!.solution).toContain("openssl");
    expect(b!.solution).toContain("[vendor-updated tag]");
  });

  it("gives Fathom's script the vendor-updated advice rather than telling the site to pin it", async () => {
    const [v] = await checkSRI(page("https://cdn.usefathom.com/script.js"), "https://vuejs.org/");
    expect(v!.evidence).toContain("[vendor-updated tag]");
    expect(v!.solution).not.toContain("openssl");
  });

  it("treats HubSpot's own CDNs as first-party, and still reports a real third party", async () => {
    const lines = (await checkSRI(page("https://static.hsappstatic.net/a/b.js", "https://js.hs-banner.com/v2/1/banner.js", "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"), "https://www.hubspot.com/")).flatMap((v) => (v.evidence ?? "").split("\n"));
    expect(lines.some((l) => l.includes("hsappstatic.net") || l.includes("hs-banner.com"))).toBe(false);
    expect(lines.some((l) => l.includes("lodash"))).toBe(true);
    expect(await checkSRI(page("https://static.hsappstatic.net/a/b.js"), "https://www.example.com/")).not.toEqual([]);
  });

  it("treats the Guardian's guim.co.uk as its own CDN", async () => {
    expect(await checkSRI(page("https://assets.guim.co.uk/a.js"), "https://www.theguardian.com/")).toEqual([]);
  });
});
