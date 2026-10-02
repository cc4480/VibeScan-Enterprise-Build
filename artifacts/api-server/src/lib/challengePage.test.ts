import { describe, it, expect } from "vitest";
import { detectChallengePage } from "./challengePage.js";
import { withholdInterceptedFindings } from "./scanner.js";

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

describe("the two other pages amazon.co.uk returns instead of its homepage", () => {
  // Found by re-running the 30-site sweep on 2026-09-24: both came back as HTTP 200,
  // neither matched a fingerprint, and the scan reported "Missing Content-Security-
  // Policy" (HIGH) plus four more findings about a page Amazon never published.
  // Sanitised from the live responses: tokens removed, structure kept.

  // Served to a browser-style client: Akamai Bot Manager, ~2 KB.
  const AKAMAI_INTERSTITIAL = `<!DOCTYPE html><html><head> <meta charset="utf-8"> <meta http-equiv="refresh" content="5; URL='/?bm-verify=TOKEN'" /><title>&nbsp;</title><script> var i = 1; var j = i + Number("3950" + "27162"); </script> </head> <body> <iframe style="border: none; width: 100vw; height: 100vh;" src="https://m.media-amazon.com/images/S/sash/x.gif"> </iframe> <script> function triggerInterstitialChallenge() {var xhr = new XMLHttpRequest(); xhr.open("POST", "/_sec/verify?provider=interstitial", false); xhr.send(JSON.stringify({"bm-verify": "TOKEN", "pow": j}));} triggerInterstitialChallenge(); </script> </body> </html>`;

  // Served to a plain client: the "Continue shopping" robot check, ~4 KB.
  const AMAZON_ROBOT_CHECK = `<!DOCTYPE html><html class="a-no-js" lang="en-us"><head><meta charset="utf-8"><title dir="ltr">Amazon.co.uk</title></head><body>
<div class="a-container"><div class="a-box a-alert a-alert-info"><h4>Click the button below to continue shopping</h4></div>
<form method="get" action="/errors_page/validateCaptcha" name=""><input type="hidden" name="amzn" value="TOKEN" />
<button type="submit" class="a-button-text" alt="Continue shopping">Continue shopping</button></form></div></body></html>`;

  it("flags the Akamai Bot Manager interstitial", () => {
    const v = detectChallengePage(200, AKAMAI_INTERSTITIAL, { server: "AkamaiGHost" });
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("Akamai Bot Manager");
  });

  it("flags it without the server header too, on its own script", () => {
    expect(detectChallengePage(200, AKAMAI_INTERSTITIAL).isChallenge).toBe(true);
  });

  it("flags the Amazon robot check even though its title is just 'Amazon.co.uk'", () => {
    // The title carries no signal, which is why only the form target can catch it.
    const v = detectChallengePage(200, AMAZON_ROBOT_CHECK);
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("Amazon");
  });

  it("does not flag a real page that merely mentions the words", () => {
    const html = `<html><head><title>Bot management guide</title></head><body><h1>Interstitial challenges</h1><p>Vendors verify a browser with a challenge; the bm-verify idea and a captcha form are explained below.</p>${"<p>text</p>".repeat(400)}</body></html>`;
    expect(detectChallengePage(200, html).isChallenge).toBe(false);
  });

  it("does not flag a large real page that links to a captcha endpoint", () => {
    // Above the interstitial size ceiling, a page is real whatever it loads.
    const html = `<html><head><title>Shop</title></head><body>${"<p>product</p>".repeat(6000)}<form action="/errors_page/validateCaptcha"></form></body></html>`;
    expect(html.length).toBeGreaterThan(60_000);
    expect(detectChallengePage(200, html).isChallenge).toBe(false);
  });
});

// ─── Suppression of findings read from an interstitial ───────────────────────

describe("withholdInterceptedFindings", () => {
  // The shape of the etsy.com scan: 12 of 18 findings came from Cloudflare's
  // interstitial, including "Missing Content-Security-Policy" and a wildcard
  // CORS policy — both false about Etsy.
  const scan = [
    { category: "Injection Defense", name: "Missing Content-Security-Policy (CSP)" },
    { category: "CORS Misconfiguration", name: "Permissive CORS Policy (Wildcard Origin)" },
    { category: "Session Management", name: "Non-Session Cookie Readable by JavaScript" },
    { category: "Supply Chain Security", name: "External Resources Missing SRI" },
    { category: "UI Security", name: "Missing Clickjacking Protection (X-Frame-Options)" },
    { category: "Email Security", name: "SPF Record Exceeds DNS Lookup Limit" },
    { category: "DNS Security", name: "DNSSEC Not Enabled" },
    { category: "Scan Coverage", name: "Scan was intercepted by a bot-protection challenge" },
  ] as unknown as Parameters<typeof withholdInterceptedFindings>[0];

  it("withholds everything read from the response when intercepted", () => {
    const kept = withholdInterceptedFindings(scan, true);
    expect(kept.map((f) => f.category)).toEqual([
      "Email Security",
      "DNS Security",
      "Scan Coverage",
    ]);
  });

  it("does not attribute the interstitial's missing headers to the target", () => {
    const kept = withholdInterceptedFindings(scan, true);
    expect(kept.some((f) => /Content-Security-Policy/.test(f.name))).toBe(false);
    expect(kept.some((f) => /CORS/.test(f.name))).toBe(false);
    expect(kept.some((f) => /Clickjacking/.test(f.name))).toBe(false);
  });

  it("keeps the coverage notice, so the scan cannot read as clean", () => {
    const kept = withholdInterceptedFindings(scan, true);
    expect(kept.some((f) => /intercepted/i.test(f.name))).toBe(true);
  });

  it("changes nothing on a scan that was not intercepted", () => {
    expect(withholdInterceptedFindings(scan, false)).toHaveLength(scan.length);
  });
});

describe("the markup Cloudflare actually emits", () => {
  // `\bcf_chl_opt\b` never matched `window._cf_chl_opt={...}` — "_" is a word
  // character, so there is no boundary before "cf". Found while porting this
  // file to seclayer.io2026, where a test of the live form failed.
  it.each([
    'window._cf_chl_opt={cvId:"3"};',
    'window.__cf_chl_tk="abc";',
    '<script>cf_chl_opt</script>',
  ])("detects %s", (body) => {
    const v = detectChallengePage(403, `<html><head><title>x</title></head><body>${body}</body></html>`);
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("Cloudflare");
  });
});

describe("vendor sensor tags are not interstitials", () => {
  // Same class as the Cloudflare /cdn-cgi/challenge-platform/ bug: the reference
  // to a bot-protection vendor's script is on the customer's ordinary pages.
  const page = (head: string, body = `<h1>Acme Widgets</h1><nav>Shop</nav><p>${"Welcome to our shop. ".repeat(40)}</p>`) =>
    `<!doctype html><html><head><title>Acme Widgets - Home</title>${head}</head><body>${body}</body></html>`;

  it.each([
    ["DataDome tags.js", page(`<script src="https://js.datadome.co/tags.js" async></script>`)],
    ["Imperva injected resource", page(`<script src="/_Incapsula_Resource?SWJIYLWA=5074a744,719d34d3"></script>`)],
    ["PerimeterX sensor", page(`<script src="https://client.perimeterx.net/PXabc123/main.min.js"></script>`)],
    ["AWS WAF SDK", page(`<script src="https://1234.edge.sdk.awswaf.com/1234/567/challenge.js"></script>`)],
    ["blog post about datadome", page("", "<p>We evaluated datadome and perimeterx and awswaf.com for bot mitigation.</p>")],
    ["tiny page, vendor only in prose", `<html><body>datadome perimeterx _Incapsula_Resource</body></html>`],
  ])("leaves an ordinary page with %s alone", (_n, html) => {
    expect(detectChallengePage(200, html, {}).isChallenge).toBe(false);
  });

  it.each([
    ["Imperva JS challenge stub", `<html style="height:100%"><head><META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW"></head><body style="margin:0px;height:100%"><iframe id="main-iframe" src="/_Incapsula_Resource?SWUDNSAI=31&xinfo=1-2" frameborder=0 width="100%" height="100%"></iframe></body></html>`],
    ["AWS WAF challenge stub", `<html><head></head><body><script src="https://1234.edge.sdk.awswaf.com/1234/567/challenge.js"></script><script>AwsWafIntegration.saveReferrer();AwsWafIntegration.checkForceRefresh();</script></body></html>`],
    ["DataDome stub", `<html><head><meta name="robots" content="noindex"></head><body><script src="https://js.datadome.co/captcha.js"></script></body></html>`],
    ["PerimeterX stub", `<html><body><script src="https://client.perimeterx.net/PXabc123/captcha.js"></script></body></html>`],
  ])("still flags the %s", (_n, html) => {
    expect(detectChallengePage(200, html, {}).isChallenge).toBe(true);
  });

  it("still flags PerimeterX's Press & Hold container on a larger block page", () => {
    expect(detectChallengePage(403, `<html><body><div id="px-captcha"></div>${"<i></i>".repeat(500)}</body></html>`).isChallenge).toBe(true);
  });
});

describe("detectChallengePage — signals checked against wafw00f (2026-10-02)", () => {
  it("a page that only names Sucuri's firewall is not a block page", () => {
    expect(detectChallengePage(200, "<html><body><p>We protect sites with Sucuri WebSite Firewall.</p></body></html>").isChallenge).toBe(false);
  });
  it("Sucuri's own block page is", () => {
    const v = detectChallengePage(403, "<html><head><title>Sucuri WebSite Firewall - Access Denied</title></head><body>x</body></html>");
    expect(v.vendor).toBe("Sucuri");
  });
  it("PerimeterX's block text and Vercel's checkpoint path are", () => {
    expect(detectChallengePage(403, "<html><body><p>Request blocked: denied because we believe you are using automation tools</p></body></html>").vendor).toBe("PerimeterX");
    expect(detectChallengePage(429, `<html><body><script src="/vercel/security/static/challenge.js"></script></body></html>`).vendor).toBe("Vercel");
  });
});
