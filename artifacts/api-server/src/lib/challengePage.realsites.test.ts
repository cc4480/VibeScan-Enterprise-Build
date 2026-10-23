import { describe, it, expect } from "vitest";
import { detectChallengePage } from "./challengePage.js";
import { withholdInterceptedFindings } from "./scanner.js";

/** The verbatim shape of Cloudflare's interstitial, as in challengePage.test.ts. */
const CLOUDFLARE_403 = `<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>
<meta name="robots" content="noindex,nofollow"></head><body class="no-js"><div class="main-wrapper" role="main">
<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script>
</div></body></html>`;

// ─── Real responses that were misjudged (verified 2026-09-29) ────────────────
//
// Three findings from real-site verification named this detector. Each fixture is
// what the server actually sent, saved under __fixtures__/. Byte counts match the
// captures the verifier reported: reddit 8,397, microsoft 201,253, secscan.us 22,966.

import { readFileSync } from "node:fs";

const fixture = (name: string): string =>
  readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), "utf8");

describe("Reddit's proof-of-work interstitial (www.reddit.com, 2026-09-29)", () => {
  // GET / answers 200 with a hidden GET form (solution, js_challenge=1, jsc_token) that a
  // script fills and auto-submits. It carries its own CSP ("default-src 'none'; ..."), so the
  // crawler took that CSP as the site's baseline and reported "Content-Security-Policy Missing
  // on 6 Internal Routes" against pages that were never compared with Reddit's real ones.
  const body = fixture("reddit-challenge.html");
  const headers = {
    server: "snooserv",
    "content-type": "text/html",
    "content-security-policy":
      "default-src 'none'; script-src 'nonce-b53c6e07-e81e-4c74-b49e-65dd3b6bfc23'; style-src 'unsafe-inline'; img-src https://www.redditstatic.com; form-action 'self';",
  };

  it("is the real 8,397-byte capture", () => {
    expect(Buffer.byteLength(body)).toBe(8397);
  });

  it("is recognised as a challenge", () => {
    const v = detectChallengePage(200, body, headers);
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("Reddit");
  });

  it("is recognised without the response headers, on the form alone", () => {
    expect(detectChallengePage(200, body).isChallenge).toBe(true);
  });

  it("does not flag a page that merely has a form with a field called 'solution'", () => {
    // Both markers are needed together: js_challenge and jsc_token. A quiz site's
    // 'solution' input, or a page discussing the parameters, is not an interstitial.
    const quiz = `<html><head><title>Reddit</title></head><body><form hidden method="GET" action="/">
      <input type="hidden" name="solution" /></form>${"<p>post</p>".repeat(50)}</body></html>`;
    expect(detectChallengePage(200, quiz).isChallenge).toBe(false);
    const prose = `<html><head><title>Docs</title></head><body><p>Reddit sends js_challenge=1 and a jsc_token.</p></body></html>`;
    expect(detectChallengePage(200, prose).isChallenge).toBe(false);
  });
});

describe("Akamai's block page served as HTTP 200 (www.microsoft.com/en-us, 2026-09-29)", () => {
  // The capture is 201,253 bytes; the first 3,000 are kept verbatim (the <title> is in them)
  // and the tail is padded to the captured length, because the size is the point: the old
  // title rule stopped at 60,000 bytes, and this page has no Akamai host or AkamaiGHost token.
  const head = fixture("akamai-block-microsoft-head.html");
  const body = head + "<p>x</p>".repeat(Math.ceil((201_253 - head.length) / 8)).slice(0, 201_253 - head.length);

  it("has the captured size", () => {
    expect(body.length).toBe(201_253);
    expect(body.length).toBeGreaterThan(60_000);
  });

  it("is recognised as a block page even though it is large and answers 200", () => {
    const v = detectChallengePage(200, body, { server: "AkamaiNetStorage" });
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("Akamai");
    expect(v.signal).toMatch(/Your request has been blocked/);
  });

  it("is recognised with the title wrapped across lines, as served", () => {
    expect(head).toMatch(/be\s*\n\s+due to several reasons/);
    expect(detectChallengePage(200, body).isChallenge).toBe(true);
  });

  it("does not flag a large real page that only mentions the sentence", () => {
    // The rule is the whole <title>, anchored. Prose in a help article is not a block page.
    const help = `<html><head><title>Fixing 'Your request has been blocked' errors | Help Center</title></head><body>
      <p>Your request has been blocked. This could be due to several reasons.</p>${"<p>text</p>".repeat(9000)}</body></html>`;
    expect(help.length).toBeGreaterThan(60_000);
    expect(detectChallengePage(200, help).isChallenge).toBe(false);
  });
});

describe("Cloudflare's passive JS-detection script (secscan.us, 2026-09-29)", () => {
  // Cloudflare injects <script>...a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'...</script>
  // into ordinary pages it proxies. It is not an interstitial: the origin answered, the page is
  // 23 KB of the site's own markup. The old signal matched the /cdn-cgi/challenge-platform/ prefix,
  // so a clean secscan.us scan withheld every header, cookie and CSP finding, and the report read
  // as "0 actionable" about checks that never ran.
  const body = fixture("secscan-us-home.html");

  it("is the real 22,966-byte capture, and does contain the injection", () => {
    expect(Buffer.byteLength(body)).toBe(22966);
    expect(body).toContain("/cdn-cgi/challenge-platform/scripts/jsd/main.js");
  });

  it("is not a challenge", () => {
    expect(detectChallengePage(200, body, { server: "cloudflare" })).toEqual({
      isChallenge: false,
      vendor: null,
      signal: null,
    });
  });

  it("does not withhold the findings of a scan of that page", () => {
    const scan = [
      { category: "Injection Defense", name: "Missing Content-Security-Policy (CSP)" },
      { category: "Session Management", name: "Session Cookie Missing Secure Flag" },
    ] as unknown as Parameters<typeof withholdInterceptedFindings>[0];
    const verdict = detectChallengePage(200, body, { server: "cloudflare" });
    expect(withholdInterceptedFindings(scan, verdict.isChallenge)).toHaveLength(2);
  });

  it.each([
    "/cdn-cgi/challenge-platform/h/b/scripts/jsd/main.js",
    "/cdn-cgi/challenge-platform/scripts/jsd/main.js?ray=abc",
  ])("still treats %s as ordinary", (src) => {
    const html = `<html><head><title>Acme</title></head><body><p>hi</p><script src="${src}"></script></body></html>`;
    expect(detectChallengePage(200, html).isChallenge).toBe(false);
  });

  it.each([
    "/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1?ray=8a1b",
    "/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1",
    "/cdn-cgi/challenge-platform/orchestrate/managed/v1",
  ])("still catches the real interstitial script %s", (src) => {
    const html = `<html><head><title>x</title></head><body><script src="${src}"></script></body></html>`;
    const v = detectChallengePage(200, html);
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("Cloudflare");
  });

  it("catches an interstitial that also carries the passive injection", () => {
    // Both scripts on one page: the orchestrate path is what decides.
    const html = `${CLOUDFLARE_403.replace("</body>", `<script>a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'</script></body>`)}`;
    expect(detectChallengePage(200, html).isChallenge).toBe(true);
  });
});

describe("AWS WAF challenge stub with a <noscript> heading (www.booking.com, 2026-10-05)", () => {
  // GET / answered HTTP 202 with a bare document: an empty <title>, an empty #challenge-container,
  // the WAF's challenge.js and AwsWafIntegration calls, and <noscript><h1>JavaScript is disabled</h1>.
  // The <h1> made isStubDocument call it a real page, so the stub was graded as booking.com's
  // homepage: 12 findings about an interstitial nobody publishes. Saved with LF line endings (the
  // server sent CRLF; the repo normalises to LF).
  const body = fixture("aws-waf-challenge-booking.html");

  it("is the real capture", () => {
    expect(body).toContain("AwsWafIntegration.getToken()");
    expect(body).toContain("<h1>JavaScript is disabled</h1>");
  });

  it("is recognised as an AWS WAF challenge", () => {
    const v = detectChallengePage(202, body, { server: "istio-envoy" });
    expect(v.isChallenge).toBe(true);
    expect(v.vendor).toBe("AWS WAF");
  });

  it("clean twin: a real page that loads the AWS WAF SDK and has a noscript fallback is left alone", () => {
    const page = `<!doctype html><html><head><title>Acme Widgets - Home</title>
<script src="https://1234.edge.sdk.awswaf.com/1234/567/challenge.js"></script></head>
<body><h1>Acme Widgets</h1><nav>Shop</nav><p>${"Welcome to our shop. ".repeat(40)}</p>
<noscript><h1>JavaScript is disabled</h1>Enable JavaScript to use the cart.</noscript></body></html>`;
    expect(detectChallengePage(200, page, {}).isChallenge).toBe(false);
  });

  it("clean twin: a small page whose real content is outside the noscript block is left alone", () => {
    const page = `<html><head><title>Status</title><script>AwsWafIntegration.getToken()</script></head>
<body><main><p>${"All systems operational. ".repeat(12)}</p></main><noscript><h1>JavaScript is disabled</h1></noscript></body></html>`;
    expect(detectChallengePage(200, page, {}).isChallenge).toBe(false);
  });
});
