import { describe, it, expect } from "vitest";
import { cspFindings } from "./scannerCspChecks";
import { extractMetaCsp } from "./headerAnalysis";

/**
 * Found by the 2026-09-30 sweep: gitlab.com redirects to about.gitlab.com, whose response has no CSP
 * header but whose HTML carries <meta http-equiv="Content-Security-Policy">. Browsers enforce that, so
 * "Missing Content-Security-Policy" (High) was wrong as worded, and the policy's real weakness
 * ('unsafe-inline' 'unsafe-eval' in script-src) went unreported.
 */

const page = (html: string, headers: Record<string, string> = {}) => ({
  finalUrl: "https://example.com/",
  html,
  rawHeaders: headers,
  isHttps: true,
});
const names = (html: string, headers: Record<string, string> = {}) => cspFindings(page(html, headers)).map((v) => v.name);
const meta = (content: string, attrs = 'http-equiv="Content-Security-Policy"') => `<html><head><meta ${attrs} content="${content}"></head><body></body></html>`;

describe("extractMetaCsp", () => {
  it("reads the policy whatever the attribute order, quoting, case or line breaks", () => {
    expect(extractMetaCsp(`<meta content="default-src 'self'" http-equiv="Content-Security-Policy">`)).toBe("default-src 'self'");
    expect(extractMetaCsp(`<META HTTP-EQUIV='content-security-policy' CONTENT='default-src "none"'>`)).toBe(`default-src "none"`);
    expect(extractMetaCsp(`<meta hid="csp" http-equiv="Content-Security-Policy" content="
        default-src 'self' https: http:;
        script-src 'self' 'unsafe-inline';
      ">`)).toBe("default-src 'self' https: http:; script-src 'self' 'unsafe-inline';");
  });
  it("decodes the entities an HTML attribute may carry", () => {
    expect(extractMetaCsp(`<meta http-equiv="Content-Security-Policy" content="img-src &#39;self&#39; data:; connect-src https://a.example/?x=1&amp;y=2">`)).toBe(
      "img-src 'self' data:; connect-src https://a.example/?x=1&y=2",
    );
  });
  it("does not mistake other meta tags, page text, comments or a report-only tag for a policy", () => {
    expect(extractMetaCsp(`<meta name="description" content="Content-Security-Policy: default-src 'self'">`)).toBeNull();
    expect(extractMetaCsp(`<p>Set http-equiv="Content-Security-Policy" content="default-src 'self'" in your head</p>`)).toBeNull();
    expect(extractMetaCsp(`<!-- <meta http-equiv="Content-Security-Policy" content="default-src 'self'"> -->`)).toBeNull();
    expect(extractMetaCsp(`<meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'self'">`)).toBeNull();
    expect(extractMetaCsp(`<meta http-equiv="Content-Security-Policy" content="">`)).toBeNull();
    expect(extractMetaCsp("<html></html>")).toBeNull();
  });
});

describe("cspFindings with a policy delivered by <meta>", () => {
  it("does not report a missing CSP when the page has an enforced meta policy", () => {
    const n = names(meta("default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'"));
    expect(n).not.toContain("Missing Content-Security-Policy (CSP)");
    expect(n).toEqual([]);
  });

  it("analyses a weak meta policy like a header's, and says where it came from", () => {
    const vulns = cspFindings(page(meta("default-src 'self' https: http:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https: http:")));
    const weak = vulns.find((v) => /^Weak Content-Security-Policy/.test(v.name));
    expect(weak).toBeDefined();
    expect(weak!.severity).toBe("medium");
    expect(weak!.evidence).toContain('<meta http-equiv="Content-Security-Policy"');
    expect(vulns.map((v) => v.name)).not.toContain("Missing Content-Security-Policy (CSP)");
  });

  it("reports the directives a meta policy lacks (base-uri, object-src)", () => {
    const n = names(meta("default-src 'self'"));
    expect(n.some((x) => /base-uri/i.test(x))).toBe(true);
  });

  it("prefers the header when both are present", () => {
    const n = names(meta("script-src 'unsafe-inline'"), { "content-security-policy": "default-src 'none'; base-uri 'none'" });
    expect(n.some((x) => /^Weak Content-Security-Policy/.test(x))).toBe(false);
  });
});

describe("cspFindings still reports what is really missing", () => {
  it("reports High when there is neither a header nor a meta policy, and says both were looked for", () => {
    const [v] = cspFindings(page("<html><head><title>x</title></head></html>"));
    expect(v!.name).toBe("Missing Content-Security-Policy (CSP)");
    expect(v!.severity).toBe("high");
    expect(v!.evidence).toContain("no <meta http-equiv> policy");
  });
  it("does not accept a commented-out or report-only meta tag as a policy", () => {
    expect(names(`<!-- ${meta("default-src 'self'")} -->`)).toContain("Missing Content-Security-Policy (CSP)");
    expect(names(meta("default-src 'self'", 'http-equiv="Content-Security-Policy-Report-Only"'))).toContain("Missing Content-Security-Policy (CSP)");
  });
  it("still reports a header that is report-only as report-only", () => {
    expect(names("<html></html>", { "content-security-policy-report-only": "default-src 'self'" })).toContain(
      "Content-Security-Policy is report-only (not enforced)",
    );
  });
});

describe("unsafe-inline in style-src alone", () => {
  const strictScripts = { "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" };

  it("is reported as information that needs verification, not as a weakness that weighs on the grade", () => {
    const found = cspFindings(page("<html></html>", strictScripts)).find((v) => /Allows Inline Styles/.test(v.name));
    expect(found).toBeDefined();
    expect(found!.severity).toBe("info");
    // Below the report's verification threshold (65), so it is listed under "Needs verification".
    expect(found!.confidence).toBeLessThan(65);
    expect(found!.cvssScore).toBe(0);
  });

  it("is still a medium finding when scripts themselves allow unsafe-inline", () => {
    const weak = { "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" };
    const found = cspFindings(page("<html></html>", weak)).find((v) => /Weak Content-Security-Policy/.test(v.name));
    expect(found?.severity).toBe("medium");
  });
});

describe("object-src falls back to default-src (Google CSP Evaluator behaviour)", () => {
  const found = (csp: string) => cspFindings(page("<html></html>", { "content-security-policy": csp })).some((v) => /object-src/.test(v.name));

  it("does not flag a policy whose default-src already confines plugin content", () => {
    expect(found("default-src 'self'; script-src 'self'")).toBe(false);
    expect(found("default-src 'none'; script-src 'self'")).toBe(false);
    expect(found("script-src 'self'; object-src 'none'")).toBe(false);
    expect(found("script-src 'self'; object-src 'self'")).toBe(false);
  });

  it("clean twin: flags a policy with no object-src and no default-src, or one that allows any origin or data:", () => {
    expect(found("script-src 'self'")).toBe(true);
    expect(found("default-src *; script-src 'self'")).toBe(true);
    expect(found("script-src 'self'; object-src data:")).toBe(true);
    expect(found("default-src https:; script-src 'self'")).toBe(true);
  });
});
