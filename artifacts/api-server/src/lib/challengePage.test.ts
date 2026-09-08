import { describe, it, expect } from "vitest";
import { detectChallengePage } from "./challengePage.js";

/** The verbatim shape of the pages that prompted this module. */
const CLOUDFLARE_403 = `<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width,initial-scale=1">
</head><body class="no-js"><div class="main-wrapper" role="main">
<div id="challenge-error-text">Enable JavaScript and cookies to continue</div>
<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script>
</div></body></html>`;

describe("detectChallengePage", () => {
  it("identifies the Cloudflare interstitial that started this", () => {
    // stackoverflow.com and npmjs.com both returned exactly this to the
    // scanner, and its noindex was reported as their homepages being excluded
    // from search results.
    const v = detectChallengePage(403, CLOUDFLARE_403, { server: "cloudflare" });
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("Cloudflare");
  });

  it("identifies a challenge that returns HTTP 200", () => {
    // Status is not the signal. An interstitial served as 200 is the case most
    // likely to be mistaken for a real page.
    expect(detectChallengePage(200, CLOUDFLARE_403).isChallenge).toBe(true);
  });

  it("trusts the cf-mitigated header on its own", () => {
    const v = detectChallengePage(200, "<html><body>anything</body></html>", {
      "cf-mitigated": "challenge",
    });
    expect(v.isChallenge).toBe(true);
    expect(v.signal).toContain("cf-mitigated");
  });

  it.each([
    ["Imperva", `<html><head><title>Blocked</title></head><body>Request unsuccessful. Incapsula incident ID: 1234</body></html>`],
    ["Akamai", `<html><body>Reference #18.2f3 <a href="https://errors.edgesuite.net/18.2f3">more</a></body></html>`],
    ["Sucuri", `<html><head><title>Sucuri WebSite Firewall - Access Denied</title></head><body>x</body></html>`],
    ["DataDome", `<html><body><script src="https://geo.captcha-delivery.com/captcha/"></script></body></html>`],
  ])("identifies a %s block page", (_vendor, html) => {
    expect(detectChallengePage(403, html).isChallenge).toBe(true);
  });

  it("treats a near-empty 403 as an interception even unsigned", () => {
    const v = detectChallengePage(403, "<html><body>Forbidden</body></html>");
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBeNull();
  });

  it("treats a 202 stub with no body as ordinary, not a challenge", () => {
    // amazon.co.uk answers 202 with 49 bytes. It is not a challenge page, and
    // claiming a vendor blocked us would be inventing a fact.
    expect(detectChallengePage(202, "<html><head></head><body></body></html>").isChallenge).toBe(false);
  });
});

describe("detectChallengePage does not cry wolf", () => {
  it("leaves a normal page alone", () => {
    const html = `<html><head><title>Acme — Home</title></head><body><h1>Welcome</h1>${"<p>copy</p>".repeat(200)}</body></html>`;
    expect(detectChallengePage(200, html, { server: "cloudflare" })).toMatchObject({ isChallenge: false });
  });

  it("does not match the phrase 'just a moment' in ordinary prose", () => {
    // The single most likely false positive: an English phrase in body copy.
    // Only a document whose entire title is the interstitial counts.
    const html = `<html><head><title>Blog — Waiting Well</title></head><body>
      <p>Give it just a moment and the coffee will be ready.</p>
      <p>Checking your browser is something websites do.</p>${"<p>x</p>".repeat(200)}</body></html>`;
    expect(detectChallengePage(200, html).isChallenge).toBe(false);
  });

  it("does not flag a real page that merely loads a bot-protection script", () => {
    // A large document referencing a vendor is a site using the product, not a
    // site being blocked by it.
    const html = `<html><head><title>Shop</title></head><body>
      <script src="https://client.perimeterx.net/px.js"></script>
      ${"<div>product</div>".repeat(6000)}</body></html>`;
    expect(html.length).toBeGreaterThan(60_000);
    expect(detectChallengePage(200, html).isChallenge).toBe(false);
  });

  it("does not flag a genuine 403 that returns a real page", () => {
    // A substantial 403 is an application's own access-denied page, which is
    // worth scanning and reporting on.
    const html = `<html><head><title>Access denied — Acme Portal</title></head><body>
      <h1>You do not have permission</h1>${"<p>Contact your administrator.</p>".repeat(200)}</body></html>`;
    expect(detectChallengePage(403, html).isChallenge).toBe(false);
  });

  it("does not flag an empty 200", () => {
    expect(detectChallengePage(200, "").isChallenge).toBe(false);
  });
});

describe("header values decide, not header presence", () => {
  it("does not flag nytimes.com, which serves its real page under x-datadome: protected", () => {
    // Regression: the header was treated as a verdict. DataDome sets it on
    // allowed traffic too, so the NYT homepage — 1.3MB with two JSON-LD blocks
    // — was reported as blocked with its content sitting in the response body.
    const html = `<html><head><title>The New York Times - Breaking News</title></head><body>${"<p>news</p>".repeat(9000)}</body></html>`;
    expect(detectChallengePage(200, html, { "x-datadome": "protected" }).isChallenge).toBe(false);
  });

  it("still flags a DataDome response that says it blocked the request", () => {
    expect(detectChallengePage(403, "<html><body>nope</body></html>", { "x-datadome": "blocked" }).isChallenge).toBe(true);
  });

  it("flags the AWS WAF challenge amazon.co.uk actually returns", () => {
    // 202 with an empty body and x-amzn-waf-action: challenge.
    const v = detectChallengePage(202, "", { "x-amzn-waf-action": "challenge" });
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("AWS WAF");
  });
});
