import { analyzeCsp, extractMetaCsp, parseCsp } from "./headerAnalysis.js";
import { headerVal, vuln, type ScanVulnerability, type PageContext } from "./scannerTypes";

/** Content-Security-Policy presence and deep analysis of the policy. */
export function cspFindings({ finalUrl, rawHeaders, html }: PageContext): ScanVulnerability[] {
  const vulnerabilities: ScanVulnerability[] = [];

  // ── Content-Security-Policy ───────────────────────────────────────────
  const headerCsp = headerVal(rawHeaders, "content-security-policy");
  // A policy delivered in <meta http-equiv="Content-Security-Policy"> is enforced by browsers, so a page
  // with one is not "missing" a CSP; it is analysed like a header's. (frame-ancestors, report-uri and
  // sandbox are ignored in a meta tag, which the clickjacking check accounts for by reading headers only.)
  const metaCsp = headerCsp ? null : extractMetaCsp(html);
  const csp = headerCsp ?? metaCsp ?? undefined;
  const shown = metaCsp ? `<meta http-equiv="Content-Security-Policy" content="${csp}"> (no CSP header)` : `Content-Security-Policy: ${csp}`;
  // A report-only policy is not enforcement — the browser reports the
  // violation and runs the script anyway — so its presence is still a finding.
  // But it is a different finding, and saying "header absent from response"
  // about a site plainly running a CSP in report-only mode is wrong, and reads
  // as a false positive to anyone who checks. google.com does exactly this.
  const cspReportOnly = headerVal(rawHeaders, "content-security-policy-report-only");
  if (!csp && cspReportOnly) {
    vulnerabilities.push(vuln({
      name: "Content-Security-Policy is report-only (not enforced)",
      severity: "medium",
      category: "Injection Defense",
      description:
        "A Content-Security-Policy is present but sent as Content-Security-Policy-Report-Only. In that mode the browser reports violations and still executes the offending script, so the policy provides no protection against Cross-Site Scripting — it only shows what a real policy would have blocked. This is the correct way to trial a policy, and is a problem only if it was meant to be enforcing.",
      evidence: `GET ${finalUrl}
Content-Security-Policy: (absent)
Content-Security-Policy-Report-Only: ${cspReportOnly.slice(0, 200)}`,
      solution:
        "Once the violation reports are clean, send the same policy as Content-Security-Policy to begin enforcing it. Sending both during the transition is fine.",
      cweId: "CWE-79",
      cvssScore: 5.3,
      wstgId: "WSTG-CONF-12",
    }));
  } else if (!csp) {
    vulnerabilities.push(vuln({
      name: "Missing Content-Security-Policy (CSP)",
      severity: "high",
      category: "Injection Defense",
      description: "No Content-Security-Policy header was found. CSP is the primary browser-enforced defense against Cross-Site Scripting (XSS) attacks. Without it, injected scripts can run with full page privileges and steal session cookies or credentials.",
      evidence: `GET ${finalUrl}\nContent-Security-Policy: (header absent from response, and no <meta http-equiv> policy in the page)`,
      solution: "Implement a strict CSP. A starting point: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'. Tighten over time using CSP violation reports.",
      cweId: "CWE-79",
      cvssScore: 7.2,
      wstgId: "WSTG-CONF-12",
    }));
  } else {
    // Directives are parsed in headerAnalysis.ts. 'unsafe-inline' next to a nonce, hash
    // or 'strict-dynamic' is ignored by browsers, and 'wasm-unsafe-eval' is not
    // 'unsafe-eval', so neither counts as weakness.
    //   • unsafe-inline / unsafe-eval in script-src → MEDIUM (XSS, scripts execute)
    //   • unsafe-inline ONLY in style-src (script-src is clean) → INFO, "needs verification" (CSS injection
    //     only: can spoof UI, but cannot run JS, and a modern front end that injects its own styles at runtime
    //     often cannot drop it without breaking). Shown, never hidden, but it does not weigh on the grade.
    const cspVerdict = analyzeCsp(csp);
    const scriptHasUnsafe = cspVerdict.scriptUnsafeInline || cspVerdict.scriptUnsafeEval;
    const styleOnlyUnsafe = cspVerdict.styleUnsafeInline && !scriptHasUnsafe;

    if (scriptHasUnsafe) {
      vulnerabilities.push(vuln({
        name: "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)",
        severity: "medium",
        category: "Injection Defense",
        description: "The Content-Security-Policy allows 'unsafe-inline' or 'unsafe-eval' in script-src (or default-src). This significantly weakens XSS protection — attackers who achieve HTML injection can execute arbitrary JavaScript in the page's security context.",
        evidence: `GET ${finalUrl}\n${shown}\n(${[cspVerdict.scriptUnsafeInline && "unsafe-inline (no nonce/hash/strict-dynamic to override it)", cspVerdict.scriptUnsafeEval && "unsafe-eval"].filter(Boolean).join(" and ")} in effect for scripts)`,
        solution: "Replace 'unsafe-inline' with nonce-based or hash-based CSP directives. Avoid 'unsafe-eval' entirely. Use a CSP evaluator (csp-evaluator.withgoogle.com) to audit your policy.",
        cweId: "CWE-79",
        cvssScore: 5.4,
        wstgId: "WSTG-CONF-12",
      }));
    } else if (styleOnlyUnsafe) {
      vulnerabilities.push(vuln({
        name: "Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src)",
        severity: "info",
        // Under the report's verification threshold (65), so it is listed under "Needs verification": whether it is worth
        // removing depends on whether the site's own front end can work without it.
        confidence: 50,
        category: "Injection Defense",
        description: "The Content-Security-Policy permits 'unsafe-inline' in style-src. Script execution is properly restricted (script-src has no unsafe-inline). CSS injection cannot execute JavaScript but can enable visual spoofing, clickjacking, and CSS-based data exfiltration via attribute selectors.",
        evidence: `GET ${finalUrl}\n${shown}\n(unsafe-inline in style-src only — script-src is clean, no JS execution risk)`,
        solution: "For the strongest defence, replace style-src 'unsafe-inline' with nonce-based or hash-based directives. For Tailwind CSS builds, all styles compile to an external stylesheet in production — unsafe-inline can usually be removed once any remaining inline style= attributes are eliminated.",
        cweId: "CWE-79",
        cvssScore: 0,
        wstgId: "WSTG-CONF-12",
      }));
    }
  }

  // ── CSP deep analysis (when CSP exists) ──────────────────────────────
  if (csp) {
    // object-src 'none' prevents Flash/Java plugins and data: URI XSS escalation
    // object-src falls back to default-src, so the effective source list is what counts (as Google's CSP Evaluator does):
    // default-src 'self' already confines plugin content to the site's own origin. Flag it only when nothing restricts it,
    // or what restricts it allows any origin or a data: or scheme-wide source.
    {
      const dirs = parseCsp(csp);
      const effective = dirs.get("object-src") ?? dirs.get("default-src");
      const restricted = effective !== undefined && !effective.some((t) => /^(?:\*|data:|https?:|'unsafe-inline')$/i.test(t));
      if (!restricted) {
        vulnerabilities.push(vuln({
          name: "CSP Missing object-src 'none' Directive",
          severity: "low",
          category: "Injection Defense",
          description: "The Content-Security-Policy does not include 'object-src: none'. Without this, browsers may allow Flash, Java, or other plugin content to load, which can bypass script-src restrictions entirely. XSS via plugin content is a known CSP bypass technique.",
          evidence: `GET ${finalUrl}\n${shown}\n(object-src directive absent — plugin content unrestricted)`,
          solution: "Add object-src 'none' to your CSP. If you use default-src 'none', object-src is implicitly restricted.",
          cweId: "CWE-79",
          cvssScore: 4.3,
          wstgId: "WSTG-CONF-12",
        }));
      }
    }

    // base-uri restriction prevents base-tag injection attacks
    if (!/base-uri/i.test(csp)) {
      vulnerabilities.push(vuln({
        name: "CSP Missing base-uri Directive",
        severity: "low",
        category: "Injection Defense",
        description: "The Content-Security-Policy does not restrict base-uri. Without this directive, an attacker who can inject a <base href='https://attacker.com'> tag can redirect all relative URLs on the page to their own server, hijacking resource loads and form submissions.",
        evidence: `GET ${finalUrl}\n${shown}\n(base-uri directive absent)`,
        solution: "Add base-uri 'self' to your CSP to prevent base-tag injection attacks.",
        cweId: "CWE-79",
        cvssScore: 3.5,
        wstgId: "WSTG-CONF-12",
      }));
    }

    // A wildcard only defeats CSP when it allows ANY origin. The old check was
    // /script-src\s+[^;]*\*/ — any asterisk anywhere in the directive — which
    // fires on ordinary allowlist entries like https://*.onetrust.com or
    // *.google-analytics.com. Almost every CSP that loads analytics has one, so a
    // well-built policy was reported HIGH as "XSS Protection Bypassed":
    // cloudflare.com and mozilla.org both were, on CSPs listing ~20 named origins.
    //
    // A subdomain wildcard on a named, trusted domain is an allowlist entry, not a
    // bypass. Only a bare * (optionally scheme-prefixed) lets scripts load from
    // anywhere, so only that is reported.
    const scriptSrc = /script-src\s+([^;]*)/i.exec(csp)?.[1] ?? "";
    const allowsAnyOrigin = scriptSrc
      .split(/\s+/)
      .filter(Boolean)
      .some((src) => src === "*" || src === "*:" || /^(https?:)?\/\/\*$/i.test(src));
    if (allowsAnyOrigin) {
      vulnerabilities.push(vuln({
        name: "CSP script-src Contains Wildcard — XSS Protection Bypassed",
        severity: "high",
        category: "Injection Defense",
        description: "The script-src directive in the Content-Security-Policy contains a wildcard (*), which allows scripts to be loaded from any origin. This completely defeats the purpose of CSP as an XSS mitigation.",
        evidence: `GET ${finalUrl}\n${shown}\n(wildcard in script-src allows scripts from any origin)`,
        solution: "Remove wildcards from script-src. Use an explicit allowlist of trusted origins, or switch to nonce-based CSP: script-src 'nonce-{random}'.",
        cweId: "CWE-79",
        cvssScore: 7.2,
        wstgId: "WSTG-CONF-12",
      }));
    }
  }

  return vulnerabilities;
}
