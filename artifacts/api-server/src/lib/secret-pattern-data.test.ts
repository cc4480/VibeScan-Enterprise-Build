import { describe, it, expect } from "vitest";
import { SECRET_PATTERNS } from "./secret-pattern-data.js";

describe("SECRET_PATTERNS — Google API key is public-by-design", () => {
  const google = SECRET_PATTERNS.find((p) => /Google API Key/i.test(p.name));

  it("still matches an AIza… key", () => {
    expect(google).toBeDefined();
    expect(google!.pattern.test("AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8")).toBe(true);
  });

  it("reports it as info, not high — the key is browser-facing by design", () => {
    // youtube.com shipped a valid, referrer-restricted AIza key in its embed;
    // the old High "exposed secret" turned that into a false breach headline.
    expect(google!.severity).toBe("info");
  });

  it("still ignores obvious placeholders", () => {
    expect(google!.validate!("AIzaEXAMPLE_KEY_1234567890123456789012")).toBe(false);
  });
});

describe("SECRET_PATTERNS — a PEM header is not a private key", () => {
  const pk = SECRET_PATTERNS.find((p) => /Private Key Exposed/i.test(p.name))!;

  it("does NOT fire on a crypto library's PEM formatting template", () => {
    // JSEncrypt, loaded on countless bank login forms, builds PEM output from a
    // header literal. The bare-header pattern made that a CVSS 10.0 Critical on
    // capitalone.com — and on every other site using the library.
    const lib = 'e.prototype.getPrivateKey=function(){var t="-----BEGIN RSA PRIVATE KEY-----\n";return(t+=e.wordwrap(this.getPrivateBaseKeyB64()))}';
    expect(pk.pattern.test(lib)).toBe(false);
  });

  it("still fires on a real PEM key with newlines", () => {
    const real =
      "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIEowIBAAKCAQEA7Yn3kQ2mVrJk1pQ0zXcFbN9dLmVpQrStUvWxYzAbCdEfGhIjKl\n" +
      "-----END RSA PRIVATE KEY-----";
    expect(pk.pattern.test(real)).toBe(true);
  });

  it("still fires on a key embedded in a JS string literal", () => {
    const embedded =
      'const k = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7Yn3kQ2mVrJk1pQ0zXcFbN9dLmVpQrStUvWxYzAbCdEfGhIjKl\n";';
    expect(pk.pattern.test(embedded)).toBe(true);
  });

  it("still fires on OPENSSH and EC key variants", () => {
    for (const kind of ["OPENSSH ", "EC ", ""]) {
      const k = `-----BEGIN ${kind}PRIVATE KEY-----\nMIIEowIBAAKCAQEA7Yn3kQ2mVrJk1pQ0zXcFbN9dLmVpQrStUvWxYz\n`;
      expect(pk.pattern.test(k)).toBe(true);
    }
  });
});
