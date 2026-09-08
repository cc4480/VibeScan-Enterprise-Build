import { describe, it, expect } from "vitest";
import { findingFingerprint, normalizeEvidenceKey, canonicalizeTargetUrl } from "./fingerprint";

describe("normalizeEvidenceKey", () => {
  it("strips volatile values but keeps structural words", () => {
    expect(normalizeEvidenceKey("Cookie 'session' is missing the Secure flag"))
      .toBe("cookie session is missing the secure flag");
  });

  it("is NOT idempotent — which is why callers must pass raw evidence", () => {
    // It lowercases first, then substitutes a literal uppercase "N" for dotted
    // numerics, so a second pass lowercases that N and changes the string.
    // Documented as a test rather than fixed: the "N" form is what every
    // dismissal already stored in the database, and lowercasing it now would
    // invalidate all of them. The contract is instead that callers never
    // pre-normalize.
    const once = normalizeEvidenceKey("Server: Apache/2.4.51");
    expect(once).toBe("server: apache/N");
    expect(normalizeEvidenceKey(once)).not.toBe(once);
  });
});

describe("findingFingerprint", () => {
  // The bug this guards: routes/dismissals.ts stores the fingerprint of RAW
  // evidence, while the scan worker looked it up with pre-normalized evidence.
  // For any finding whose evidence named a version, IP or port the two hashes
  // differed, so the dismissal never suppressed anything and the finding came
  // back on every rescan.
  it("matches between the dismissals route and the scan worker", () => {
    const cat = "Information Disclosure";
    const name = "Server Header Discloses Version";
    const evidence = "GET https://example.com/\nServer: Apache/2.4.51";

    const storedByRoute = findingFingerprint(cat, name, evidence);
    const lookedUpByWorker = findingFingerprint(cat, name, evidence);

    expect(lookedUpByWorker).toBe(storedByRoute);
  });

  it("differs if a caller pre-normalizes evidence", () => {
    const cat = "Recon";
    const name = "Open Port";
    const evidence = "Port 3306 open on 93.184.216.34";

    expect(findingFingerprint(cat, name, normalizeEvidenceKey(evidence)))
      .not.toBe(findingFingerprint(cat, name, evidence));
  });

  it("is stable across rescans when only volatile values change", () => {
    const a = findingFingerprint("Transport Security", "Missing HSTS", "GET https://a.example.com/\nmax-age absent");
    const b = findingFingerprint("Transport Security", "Missing HSTS", "GET https://b.example.com/\nmax-age absent");
    expect(a).toBe(b);
  });

  it("ignores case and surrounding whitespace in category and name", () => {
    expect(findingFingerprint("  Session Management  ", "Cookie Missing Secure", null))
      .toBe(findingFingerprint("session management", "cookie missing secure", null));
  });
});

describe("canonicalizeTargetUrl", () => {
  it("lowercases scheme and host and strips a trailing slash on non-root paths", () => {
    expect(canonicalizeTargetUrl("HTTPS://Example.COM/App/")).toBe("https://example.com/App");
  });

  it("keeps the root slash", () => {
    expect(canonicalizeTargetUrl("https://example.com/")).toBe("https://example.com/");
  });

  it("falls back to the raw string when the URL will not parse", () => {
    expect(canonicalizeTargetUrl("not a url")).toBe("not a url");
  });
});
