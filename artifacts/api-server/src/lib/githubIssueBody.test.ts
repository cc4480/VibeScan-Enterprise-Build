import { describe, it, expect } from "vitest";
import { parseRepo, findingKey, issueTitle, issueBody, redactSecrets, type IssueFinding } from "./githubIssueBody";

/**
 * What goes into somebody's issue tracker comes from a scan of a third-party site, so it is cleaned on the way in. These
 * are pure functions, so the tests call them directly.
 */

const finding = (over: Partial<IssueFinding> = {}): IssueFinding => ({
  id: "f1", name: "Missing Content-Security-Policy (CSP)", severity: "high", category: "Security Headers",
  description: "The site sends no Content-Security-Policy header.", evidence: "GET https://shop.example.com/\nNo CSP header in the response.",
  solution: "Add a Content-Security-Policy header.", cweId: "CWE-693", wstgId: "WSTG-CONF-12", ...over,
});
const CTX = { targetUrl: "https://shop.example.com/", reportUrl: "https://secscan.us/report/abc" };

describe("parseRepo", () => {
  it.each([
    ["acme/website", "acme/website"],
    ["  acme/website  ", "acme/website"],
    ["https://github.com/acme/website", "acme/website"],
    ["https://www.github.com/acme/website/", "acme/website"],
    ["https://github.com/acme/website.git", "acme/website"],
    ["acme/web.site_1-2", "acme/web.site_1-2"],
  ])("%s -> %s", (input, full) => {
    expect(parseRepo(input)?.fullName).toBe(full);
  });

  it.each([
    "", "acme", "acme/", "/website", "acme/web site", "acme/website/issues", "https://gitlab.com/acme/website",
    "-acme/website", "acme/..", "acme/.", "ac me/website", "acme/web?x=1", "acme/web#x", "../../etc/passwd", "a/b/c",
  ])("refuses %j", (input) => {
    expect(parseRepo(input)).toBeNull();
  });

  it("splits owner and repo", () => {
    expect(parseRepo("acme/website")).toEqual({ owner: "acme", repo: "website", fullName: "acme/website" });
  });
});

describe("findingKey: the same problem on the same site", () => {
  it("is the same for the same site and finding, whatever the scan or the letter case", () => {
    expect(findingKey("https://shop.example.com/", "Missing CSP")).toBe(findingKey("https://SHOP.example.com/some/page", " missing csp "));
  });
  it("differs by site, by port, and by finding", () => {
    const base = findingKey("https://shop.example.com/", "Missing CSP");
    expect(findingKey("https://staging.example.com/", "Missing CSP")).not.toBe(base);
    expect(findingKey("https://shop.example.com:8443/", "Missing CSP")).not.toBe(base);
    expect(findingKey("https://shop.example.com/", "Missing HSTS")).not.toBe(base);
  });
  it("still separates sites when the address does not parse", () => {
    expect(findingKey("not a url", "x")).not.toBe(findingKey("another", "x"));
  });
});

describe("issueTitle", () => {
  it("says who filed it, how serious it is, what it is and where", () => {
    expect(issueTitle(finding(), "https://shop.example.com/")).toBe("[SecScan] High: Missing Content-Security-Policy (CSP) (shop.example.com)");
  });
  it("is one bounded line however the finding is named", () => {
    const t = issueTitle(finding({ name: `line one\nline two ${"x".repeat(500)}` }), "https://shop.example.com/");
    expect(t).not.toMatch(/[\r\n]/);
    expect(t.length).toBeLessThanOrEqual(200);
  });
  it("defuses an @mention in a finding name", () => {
    expect(issueTitle(finding({ name: "ping @octocat and @acme/security" }), "https://a.example/")).not.toMatch(/@(?=[A-Za-z0-9])/);
  });
});

describe("issueBody", () => {
  it("carries the severity, the site, the description, the evidence, the fix, the references and a link back", () => {
    const b = issueBody(finding(), CTX);
    expect(b).toContain("**High**");
    expect(b).toContain("**Site:** https://shop.example.com/");
    expect(b).toContain("### What was found");
    expect(b).toContain("The site sends no Content-Security-Policy header.");
    expect(b).toContain("### Evidence");
    expect(b).toContain("No CSP header in the response.");
    expect(b).toContain("### How to fix it");
    expect(b).toContain("CWE-693");
    expect(b).toContain("OWASP WSTG-CONF-12");
    expect(b).toContain("[this report](https://secscan.us/report/abc)");
  });

  it("says that closing the issue is not a fix check", () => {
    expect(issueBody(finding(), CTX)).toMatch(/Closing this issue does not tell SecScan/);
  });

  it("leaves out the evidence and the fix sections when there are none", () => {
    const b = issueBody(finding({ evidence: null, solution: null }), CTX);
    expect(b).not.toContain("### Evidence");
    expect(b).not.toContain("### How to fix it");
  });

  it("redacts a secret in the evidence, so it is not copied into the tracker", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const b = issueBody(finding({ name: "Environment File Exposed (.env)", evidence: `GET /.env\nAWS_ACCESS_KEY_ID=${secret}\nJWT_SECRET=Zq8vK2mT9xW4pL7cRn5Bd3Hy` }), CTX);
    expect(b).not.toContain(secret);
    expect(b).not.toContain("Zq8vK2mT9xW4pL7cRn5Bd3Hy");
  });

  it("redacts a secret in the description too", () => {
    const b = issueBody(finding({ description: "The key AKIAIOSFODNN7EXAMPLE is exposed." }), CTX);
    expect(b).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("defuses @mentions in prose, so a page cannot make SecScan notify a stranger or a team", () => {
    const b = issueBody(finding({ description: "Contact @octocat or @acme/security-team about this.", solution: "Ask @someone." }), CTX);
    expect(b).not.toMatch(/@(?=[A-Za-z0-9])/);
    expect(b).toContain("octocat");
  });

  it("escapes HTML in prose, so a finding cannot inject markup", () => {
    const b = issueBody(finding({ description: "<img src=x onerror=alert(1)> <script>x</script> & more" }), CTX);
    expect(b).not.toContain("<img");
    expect(b).not.toContain("<script>");
    expect(b).toContain("&lt;img");
    expect(b).toContain("&amp; more");
  });

  it("puts evidence in a fence that backticks inside it cannot close", () => {
    const b = issueBody(finding({ evidence: "line\n```\n# Injected heading\n![x](https://evil.example/p.png)\n````" }), CTX);
    const fence = /^(`{3,})\n/m.exec(b.split("### Evidence")[1]!)![1]!;
    expect(fence.length).toBeGreaterThanOrEqual(5);
    // The text after the opening fence is closed only by a fence of that length or more, after all of the evidence.
    const afterEvidence = b.split("### Evidence")[1]!;
    expect(afterEvidence.indexOf("# Injected heading")).toBeLessThan(afterEvidence.lastIndexOf(fence));
  });

  it("bounds a huge evidence block and a huge description", () => {
    const b = issueBody(finding({ evidence: "e".repeat(100_000), description: "d".repeat(100_000) }), CTX);
    expect(b.length).toBeLessThan(15_000);
  });

  it("copes with an empty description", () => {
    expect(issueBody(finding({ description: "" }), CTX)).toContain("_No description._");
  });
});

describe("redactSecrets", () => {
  it("redacts the value of an assignment whose name says it is secret, and keeps the name", () => {
    const out = redactSecrets(["JWT_SECRET=Zq8vK2mT9xW4pL7c", "DB_PASSWORD: hunter2hunter2", "STRIPE_API_KEY = sk_live_abcdef123456", "PORT=3000", "NODE_ENV=production"].join("\n"));
    expect(out).toContain("JWT_SECRET=<redacted>");
    expect(out).toContain("DB_PASSWORD: <redacted>");
    expect(out).toContain("STRIPE_API_KEY = <redacted>");
    expect(out).not.toContain("Zq8vK2mT9xW4pL7c");
    expect(out).not.toContain("hunter2hunter2");
    expect(out).toContain("PORT=3000");
    expect(out).toContain("NODE_ENV=production");
  });

  it("redacts quoted JSON values", () => {
    const out = redactSecrets('{"password": "correct-horse-battery", "client_secret":"abcd1234efgh", "name": "shop"}');
    expect(out).not.toContain("correct-horse-battery");
    expect(out).not.toContain("abcd1234efgh");
    expect(out).toContain('"password": "<redacted>"');
    expect(out).toContain('"name": "shop"');
  });

  it("redacts the credentials inside a connection string and keeps the host", () => {
    const out = redactSecrets("DATABASE_URL=postgres://admin:s3cr3tPass@db.internal:5432/app");
    expect(out).not.toContain("s3cr3tPass");
    expect(out).toContain("db.internal:5432/app");
  });

  it("redacts a bearer or basic Authorization header", () => {
    const out = redactSecrets(["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature", "Authorization: Basic dXNlcjpwYXNz"].join("\n"));
    expect(out).not.toContain("eyJhbGciOiJIUzI1NiJ9");
    expect(out).not.toContain("dXNlcjpwYXNz");
  });

  it("leaves ordinary text and short values alone", () => {
    const text = "The page sets a cookie named session and a token field; tokens expire. Server: nginx";
    expect(redactSecrets(text)).toBe(text);
  });
});
