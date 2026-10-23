/**
 * The finding rules of the TLS configuration check, driven by plain handshake results: no socket.
 * What the check does against a live server is in tlsCheck.test.ts.
 */
import { describe, it, expect } from "vitest";
import { tlsFindings, tlsHeadline, tlsSummary } from "./tlsCheckFindings";
import { TLS_LABEL, type TlsCertificate, type TlsHandshakeResult } from "./tlsCheckTypes";
import { findingFingerprint } from "./fingerprint";
import { ROOT_CAUSE_PATTERNS } from "./scoring-data";
import { CATALOG } from "./checkCatalog";

const NOW = new Date("2026-10-05T12:00:00Z");
const daysFromNow = (d: number) => new Date(NOW.getTime() + d * 86_400_000).toISOString();

const goodCert = (over: Partial<TlsCertificate> = {}): TlsCertificate => ({
  subject: "example.com",
  issuer: "R11",
  notBefore: daysFromNow(-30),
  notAfter: daysFromNow(60),
  subjectAltNames: ["example.com", "www.example.com"],
  hostnameMatches: true,
  hostnameError: null,
  selfSigned: false,
  keyType: "RSA",
  keyBits: 2048,
  signatureAlgorithm: "sha256WithRSAEncryption",
  ...over,
});

/** A modern, correctly configured server: TLS 1.2 and 1.3, a valid trusted certificate. */
const healthy = (over: Partial<TlsHandshakeResult> = {}): TlsHandshakeResult => ({
  host: "example.com",
  port: 443,
  protocols: {
    "TLSv1": { status: "rejected", detail: "tlsv1 alert protocol version" },
    "TLSv1.1": { status: "rejected", detail: "tlsv1 alert protocol version" },
    "TLSv1.2": { status: "accepted", detail: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    "TLSv1.3": { status: "accepted", detail: "TLS_AES_256_GCM_SHA384" },
  },
  negotiated: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", standardName: "TLS_AES_256_GCM_SHA384" },
  certificate: goodCert(),
  trusted: true,
  trustError: null,
  ...over,
});

const names = (r: TlsHandshakeResult, now = NOW) => tlsFindings(r, now).map((f) => f.name);
const one = (r: TlsHandshakeResult, name: string) => {
  const f = tlsFindings(r, NOW).find((x) => x.name === name);
  if (!f) throw new Error(`no finding named ${name}; got ${names(r).join(", ") || "none"}`);
  return f;
};

describe("key and signature", () => {
  it("medium for an RSA key below 2048 bits, and for an EC key below 224", () => {
    expect(one(healthy({ certificate: goodCert({ keyBits: 1024 }) }), "TLS Certificate Key Too Short").severity).toBe("medium");
    expect(names(healthy({ certificate: goodCert({ keyType: "EC", keyBits: 192 }) }))).toEqual(["TLS Certificate Key Too Short"]);
  });

  it("raises nothing for RSA 2048, EC 256 or Ed25519, or when the size is unknown", () => {
    expect(names(healthy({ certificate: goodCert({ keyBits: 2048 }) }))).toEqual([]);
    expect(names(healthy({ certificate: goodCert({ keyType: "EC", keyBits: 256 }) }))).toEqual([]);
    expect(names(healthy({ certificate: goodCert({ keyType: "Ed25519", keyBits: 253 }) }))).toEqual([]);
    expect(names(healthy({ certificate: goodCert({ keyType: null, keyBits: null }) }))).toEqual([]);
  });

  it("medium for a SHA-1 or MD5 signature, none for SHA-256 and up or ECDSA", () => {
    for (const alg of ["sha1WithRSAEncryption", "md5WithRSAEncryption", "ecdsa-with-SHA1", "dsaWithSHA1"]) {
      expect(names(healthy({ certificate: goodCert({ signatureAlgorithm: alg }) })), alg).toEqual(["TLS Certificate Signed With a Weak Hash"]);
    }
    for (const alg of ["sha256WithRSAEncryption", "sha384WithRSAEncryption", "ecdsa-with-SHA256", "RSASSA-PSS", "Ed25519", "1.2.3.4.5", null]) {
      expect(names(healthy({ certificate: goodCert({ signatureAlgorithm: alg }) })), String(alg)).toEqual([]);
    }
  });
});

describe("the negotiated cipher", () => {
  const withCipher = (protocol: "TLSv1.2" | "TLSv1.3", cipher: string, standardName: string | null) =>
    healthy({ negotiated: { protocol, cipher, standardName } });

  it("medium for a broken or obsolete primitive", () => {
    for (const [cipher, std] of [
      ["DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
      ["RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA"],
      ["ECDHE-RSA-DES-CBC3-SHA", null],
      ["AECDH-AES256-SHA", null],
      ["NULL-SHA256", null],
      ["EXP-RC4-MD5", null],
    ] as const) {
      expect(names(withCipher("TLSv1.2", cipher, std)), cipher).toEqual(["Weak Cipher Suite Negotiated"]);
    }
  });

  it("low when the key exchange is not ephemeral (static RSA)", () => {
    const r = withCipher("TLSv1.2", "AES128-GCM-SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256");
    expect(names(r)).toEqual(["Cipher Suite Without Forward Secrecy"]);
    expect(one(r, "Cipher Suite Without Forward Secrecy").severity).toBe("low");
  });

  it("is quiet for ECDHE/DHE suites and for every TLS 1.3 suite", () => {
    expect(names(withCipher("TLSv1.2", "ECDHE-ECDSA-CHACHA20-POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"))).toEqual([]);
    expect(names(withCipher("TLSv1.2", "DHE-RSA-AES256-GCM-SHA384", null))).toEqual([]);
    expect(names(withCipher("TLSv1.3", "TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256"))).toEqual([]);
  });

  it("does not misread AES as DES", () => {
    expect(names(withCipher("TLSv1.2", "ECDHE-RSA-AES256-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"))).toEqual([]);
  });

  it("raises no cipher finding when nothing was negotiated", () => {
    expect(names(healthy({ negotiated: null }))).toEqual([]);
  });
});

describe("what the findings look like", () => {
  const worst: TlsHandshakeResult[] = [
    healthy({ protocols: { ...healthy().protocols, "TLSv1": { status: "accepted" } } }),
    healthy({ certificate: goodCert({ notAfter: daysFromNow(-3) }) }),
    healthy({ certificate: goodCert({ notBefore: daysFromNow(3) }) }),
    healthy({ certificate: goodCert({ notAfter: daysFromNow(5) }) }),
    healthy({ certificate: goodCert({ hostnameMatches: false }), trusted: false, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT" }),
    healthy({ trusted: false, trustError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }),
    healthy({ trusted: false, trustError: "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" }),
    healthy({ certificate: goodCert({ keyBits: 1024, signatureAlgorithm: "sha1WithRSAEncryption", selfSigned: true }), trusted: false, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT" }),
    healthy({ negotiated: { protocol: "TLSv1.2", cipher: "RC4-SHA", standardName: null } }),
    healthy({ negotiated: { protocol: "TLSv1.2", cipher: "AES128-SHA", standardName: null } }),
  ];
  const all = worst.flatMap((r) => tlsFindings(r, NOW));

  it("covers every check the catalog lists for this test, and only those", () => {
    const listed = CATALOG.find((t) => t.test === "TLS configuration check")!.checks.map((c) => c.name).sort();
    expect([...new Set(all.map((f) => f.name))].sort()).toEqual(listed);
  });

  it("uses the shape other transport findings use: category, CWE, CVSS, WSTG id, confidence", () => {
    for (const f of all) {
      expect(f.category, f.name).toBe("Transport Security");
      expect(f.cweId, f.name).toMatch(/^CWE-\d+$/);
      expect(f.cvssScore, f.name).toBeGreaterThan(0);
      expect(f.wstgId, f.name).toBe("WSTG-CRYP-01");
      expect(f.confidence ?? 0, f.name).toBeGreaterThanOrEqual(80);
      expect(f.description.length, f.name).toBeGreaterThan(80);
      expect(f.solution.length, f.name).toBeGreaterThan(20);
      expect(f.evidence, f.name).toContain("example.com:443");
    }
  });

  it("grades nothing and never mentions SSL Labs or a letter grade", () => {
    for (const f of all) {
      expect(`${f.name} ${f.description} ${f.evidence} ${f.solution}`, f.name).not.toMatch(/ssl labs|qualys|\bgrade\b/i);
    }
  });

  it("is not folded together by the corroboration merge, which keys on a name pattern", () => {
    for (const f of all) {
      expect(ROOT_CAUSE_PATTERNS.some((p) => p.pattern.test(f.name)), f.name).toBe(false);
    }
  });

  it("keeps a finding's fingerprint the same between two scans of the same fault", () => {
    // The fingerprint keeps only the first 50 characters of the evidence, and a dismissed finding is
    // matched by it, so a day count that moves between scans must not fall inside them.
    const a = tlsFindings(healthy({ certificate: goodCert({ notAfter: daysFromNow(9) }) }), NOW);
    const later = new Date(NOW.getTime() + 3 * 86_400_000);
    const b = tlsFindings(healthy({ certificate: goodCert({ notAfter: daysFromNow(9) }) }), later);
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
    expect(findingFingerprint(a[0]!.category, a[0]!.name, a[0]!.evidence)).toBe(findingFingerprint(b[0]!.category, b[0]!.name, b[0]!.evidence));

    const expiredA = tlsFindings(healthy({ certificate: goodCert({ notAfter: daysFromNow(-3) }) }), NOW)[0]!;
    const expiredB = tlsFindings(healthy({ certificate: goodCert({ notAfter: daysFromNow(-3) }) }), later)[0]!;
    expect(expiredA.evidence).not.toBe(expiredB.evidence);
    expect(findingFingerprint(expiredA.category, expiredA.name, expiredA.evidence)).toBe(findingFingerprint(expiredB.category, expiredB.name, expiredB.evidence));
  });
});

describe("the summary", () => {
  it("states what was observed, with no letter grade", () => {
    const s = tlsSummary(healthy(), NOW);
    expect(s).toContain("example.com:443 negotiated TLS 1.3 with TLS_AES_256_GCM_SHA384.");
    expect(s).toContain("Protocol versions accepted: TLS 1.2, TLS 1.3.");
    expect(s).toContain("Refused by the server: TLS 1.0, TLS 1.1.");
    expect(s).toContain("certificate valid for 60 more days");
    expect(s).toContain("chain trusted");
    expect(s).toContain("RSA 2048-bit key");
    expect(s).not.toMatch(/grade|ssl labs/i);
  });

  it("says 'could not test' for a version it could not test, never 'not supported'", () => {
    const r = healthy({ protocols: { ...healthy().protocols, "TLSv1": { status: "untested", detail: "the scanner's TLS library would not offer TLS 1.0" } } });
    const s = tlsSummary(r, NOW);
    expect(s).toContain("Could not test");
    expect(s).toContain("TLS 1.0");
    expect(s).not.toMatch(/not supported/i);
  });

  it("reports a bad certificate and the SSL 2/3 limit", () => {
    const s = tlsSummary(healthy({ trusted: false, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT", certificate: goodCert({ hostnameMatches: false, notAfter: daysFromNow(-1) }) }), NOW);
    expect(s).toContain("chain not trusted (DEPTH_ZERO_SELF_SIGNED_CERT)");
    expect(s).toContain("name does not match");
    expect(s).toContain("certificate expired");
    expect(s).toContain("SSL 2.0 and SSL 3.0 are not tested");
  });

  it("gives a short headline for the test record", () => {
    expect(tlsHeadline(healthy(), NOW)).toBe("TLS 1.3 negotiated, certificate valid for 60 more days");
    expect(tlsHeadline(healthy({ negotiated: null, certificate: null }), NOW)).toBe("no protocol negotiated, certificate could not be read");
    expect(Object.values(TLS_LABEL)).toEqual(["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]);
  });
});
