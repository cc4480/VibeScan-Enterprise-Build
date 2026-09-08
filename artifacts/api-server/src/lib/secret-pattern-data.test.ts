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

describe("SECRET_PATTERNS — a JWT that identifies an account is not a credential", () => {
  // Both entries share one regex; exactly one may accept any given token.
  const high = SECRET_PATTERNS.find((p) => p.name === "Hardcoded JWT Token in Source")!;
  const info = SECRET_PATTERNS.find((p) => /JWT-Shaped Publishable Key/i.test(p.name))!;

  // The shape found on nytimes.com: an Iterate survey widget's apiKey, inside
  // Google Tag Manager. Payload is {"company_id":"…","iat":…} — no principal.
  const tenantOnly =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
    ".eyJjb21wYW55X2lkIjoiNWMwOThiM2QxNjU0YzEwMDAxMmM2OGY5IiwiaWF0IjoxNTQ2MzAwODAwfQ" +
    ".ccccccccccccccccccccccccccccccccccccccccccc";

  // Payload {"sub":"user-8814","email":"…","role":"admin","iat":…}
  const principal =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
    ".eyJzdWIiOiJ1c2VyLTg4MTQiLCJlbWFpbCI6Im9wc0BleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTU0NjMwMDgwMH0" +
    ".ccccccccccccccccccccccccccccccccccccccccccc";

  it("does not report a tenant-only token as a hardcoded credential", () => {
    expect(high.pattern.test(tenantOnly)).toBe(true);
    expect(high.validate!(tenantOnly)).toBe(false);
  });

  it("reports the tenant-only token as info instead, so the signal is not lost", () => {
    expect(info.severity).toBe("info");
    expect(info.validate!(tenantOnly)).toBe(true);
  });

  it("still reports a token carrying sub/email/role as high", () => {
    expect(high.severity).toBe("high");
    expect(high.validate!(principal)).toBe(true);
  });

  it("does not also report the credential token as publishable", () => {
    expect(info.validate!(principal)).toBe(false);
  });

  it("ignores a Supabase anon key in both entries", () => {
    const anon =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
      ".eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNTQ2MzAwODAwfQ" +
      ".ccccccccccccccccccccccccccccccccccccccccccc";
    expect(high.validate!(anon)).toBe(false);
    expect(info.validate!(anon)).toBe(false);
  });

  it("ignores anything whose payload is not JSON", () => {
    const junk = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub3RfanNvbl9hdF9hbGxfaGVyZQ.cccccccccccccc";
    expect(high.validate!(junk)).toBe(false);
    expect(info.validate!(junk)).toBe(false);
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

describe("SECRET_PATTERNS — an API key shipped to the browser is not a leaked secret", () => {
  const secret = SECRET_PATTERNS.find((p) => p.name === "Hardcoded Secret or Auth Token in Source")!;
  // Exact name: "Google API Key in Client Code (verify referrer restrictions)"
  // also contains that phrase and sits earlier in the array.
  const apiKey = SECRET_PATTERNS.find((p) => p.name === "API Key in Client Code (verify restrictions)")!;

  // zoom.us: a Coveo search widget's key inside window.__zoomCoveoConfig.
  const coveo = `apiKey: 'xxf1623479-48a6-4dce-8475-28e0b0720fbc'`;

  it("reports a client-side apiKey at info, not as a hardcoded secret", () => {
    expect(apiKey.severity).toBe("info");
    expect(apiKey.cvssScore).toBe(0);
    expect(apiKey.pattern.test(coveo)).toBe(true);
    expect(apiKey.validate!(coveo)).toBe(true);
    // The Medium pattern must not claim it at all.
    expect(secret.pattern.test(coveo)).toBe(false);
  });

  it("still reports something named a secret at medium", () => {
    const s = `client_secret: 'aG9wZWZ1bGx5X3JlYWxfc2VjcmV0X3ZhbHVl'`;
    expect(secret.severity).toBe("medium");
    expect(secret.pattern.test(s)).toBe(true);
    expect(secret.validate!(s)).toBe(true);
  });

  it("still reports an access token at medium", () => {
    const s = `access_token: 'ya29AbCdEfGh1234567890XyZqRsTuVw'`;
    expect(secret.pattern.test(s)).toBe(true);
    expect(secret.validate!(s)).toBe(true);
  });

  it("ignores placeholders in both", () => {
    for (const p of [secret, apiKey]) {
      expect(p.validate!(`apiKey: 'YOUR_API_KEY_HERE_XXXX'`), p.name).toBe(false);
      expect(p.validate!(`secret: 'aaaaaaaaaaaaaaaaaaaa'`), p.name).toBe(false);
    }
  });
});
