/**
 * The finding rules of the TLS configuration check, driven by plain handshake results: no socket.
 * What the check does against a live server is in tlsCheck.test.ts.
 */
import { describe, it, expect } from "vitest";
import { EXPIRY_WARNING_DAYS, certificateState, tlsFindings } from "./tlsCheckFindings";
import { type TlsCertificate, type TlsHandshakeResult } from "./tlsCheckTypes";

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

describe("a healthy server", () => {
  it("raises nothing", () => {
    expect(tlsFindings(healthy(), NOW)).toEqual([]);
  });

  it("raises nothing when the legacy protocols were only untested, or when TLS 1.3 is simply not offered", () => {
    const r = healthy({
      protocols: {
        "TLSv1": { status: "untested", detail: "the scanner's TLS library would not offer TLS 1.0" },
        "TLSv1.1": { status: "untested", detail: "the server closed the connection without an answer" },
        "TLSv1.2": { status: "accepted", detail: "x" },
        "TLSv1.3": { status: "rejected", detail: "tlsv1 alert protocol version" },
      },
      negotiated: { protocol: "TLSv1.2", cipher: "ECDHE-RSA-AES128-GCM-SHA256", standardName: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    });
    expect(tlsFindings(r, NOW)).toEqual([]);
  });
});

describe("protocol versions", () => {
  it("medium when TLS 1.0 or 1.1 completed a handshake, and says which", () => {
    const r = healthy({
      protocols: { ...healthy().protocols, "TLSv1": { status: "accepted", detail: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" } },
    });
    const f = one(r, "Deprecated TLS Protocol Versions Accepted");
    expect(f.severity).toBe("medium");
    expect(f.cweId).toBe("CWE-326");
    expect(f.wstgId).toBe("WSTG-CRYP-01");
    expect(f.description).toContain("TLS 1.0");
    expect(f.description).not.toContain("TLS 1.1");
    expect(f.evidence).toContain("TLS 1.0: accepted (TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)");
  });

  it("is one finding for both legacy versions, naming both", () => {
    const r = healthy({
      protocols: { ...healthy().protocols, "TLSv1": { status: "accepted" }, "TLSv1.1": { status: "accepted" } },
    });
    expect(names(r)).toEqual(["Deprecated TLS Protocol Versions Accepted"]);
    expect(one(r, "Deprecated TLS Protocol Versions Accepted").description).toContain("TLS 1.0 and TLS 1.1");
  });

  it("notes the other legacy version as untested rather than claiming it is off", () => {
    const r = healthy({
      protocols: { ...healthy().protocols, "TLSv1": { status: "accepted" }, "TLSv1.1": { status: "untested", detail: "the server closed the connection" } },
    });
    expect(one(r, "Deprecated TLS Protocol Versions Accepted").evidence).toContain("TLS 1.1: could not be tested");
  });
});

describe("certificate validity", () => {
  it("high when the certificate has expired, with how long ago", () => {
    const r = healthy({ certificate: goodCert({ notBefore: daysFromNow(-400), notAfter: daysFromNow(-3) }) });
    const f = one(r, "TLS Certificate Expired");
    expect(f.severity).toBe("high");
    expect(f.description).toContain("expired 3 days ago");
    expect(f.cweId).toBe("CWE-298");
    expect(names(r)).not.toContain("TLS Certificate Expires Soon");
  });

  it("says 'less than a day ago' for one that lapsed hours ago", () => {
    const r = healthy({ certificate: goodCert({ notAfter: new Date(NOW.getTime() - 3_600_000).toISOString() }) });
    expect(one(r, "TLS Certificate Expired").description).toContain("expired less than a day ago");
  });

  it("high when it is not valid yet", () => {
    const r = healthy({ certificate: goodCert({ notBefore: daysFromNow(2), notAfter: daysFromNow(92) }) });
    expect(one(r, "TLS Certificate Not Yet Valid").severity).toBe("high");
  });

  it(`low when fewer than ${EXPIRY_WARNING_DAYS} days remain, and not at ${EXPIRY_WARNING_DAYS}`, () => {
    const soon = healthy({ certificate: goodCert({ notAfter: daysFromNow(EXPIRY_WARNING_DAYS - 0.5) }) });
    const f = one(soon, "TLS Certificate Expires Soon");
    expect(f.severity).toBe("low");
    expect(f.description).toContain(`expires in ${EXPIRY_WARNING_DAYS - 1} days`);
    expect(names(healthy({ certificate: goodCert({ notAfter: daysFromNow(EXPIRY_WARNING_DAYS) }) }))).toEqual([]);
    expect(names(healthy({ certificate: goodCert({ notAfter: daysFromNow(80) }) }))).toEqual([]);
  });

  it("does not report a healthy short-lived certificate for being short-lived", () => {
    // Let's Encrypt's 6-day certificates always sit inside a fixed 14-day
    // window, so each one was reported as failing renewal on every scan.
    const sixDay = (remaining: number) =>
      healthy({ certificate: goodCert({ notBefore: daysFromNow(remaining - 6), notAfter: daysFromNow(remaining) }) });
    expect(names(sixDay(5))).toEqual([]);
    expect(names(sixDay(2.5))).toEqual([]);
    // Inside the last third of its life it should already have been renewed.
    const late = one(sixDay(1.5), "TLS Certificate Expires Soon");
    expect(late.description).toContain("the last third of its 6-day lifetime");
    // A 90-day certificate keeps the fixed 14-day window.
    expect(names(healthy({ certificate: goodCert({ notBefore: daysFromNow(-77), notAfter: daysFromNow(13) }) }))).toContain("TLS Certificate Expires Soon");
  });

  it("states the clock position the same way the findings use it", () => {
    expect(certificateState(goodCert(), NOW)).toEqual({ state: "valid", days: 60 });
    expect(certificateState(null, NOW)).toEqual({ state: "unknown" });
    expect(certificateState(goodCert({ notBefore: null, notAfter: null }), NOW)).toEqual({ state: "unknown" });
  });
});

describe("hostname", () => {
  it("high when the certificate does not cover the host, listing the names it does cover", () => {
    const r = healthy({ certificate: goodCert({ hostnameMatches: false, hostnameError: "Host: example.com. is not in the cert's altnames: DNS:other.test", subjectAltNames: ["other.test"] }) });
    const f = one(r, "TLS Certificate Does Not Match the Hostname");
    expect(f.severity).toBe("high");
    expect(f.cweId).toBe("CWE-297");
    expect(f.evidence).toContain("Names on the certificate: other.test");
    expect(f.solution).toContain("example.com");
  });
});

describe("chain trust", () => {
  it("high and 'self-signed' when the leaf signs itself and the scanner does not trust it", () => {
    const r = healthy({ trusted: false, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT", certificate: goodCert({ selfSigned: true }) });
    expect(names(r)).toEqual(["Self-Signed TLS Certificate"]);
    expect(one(r, "Self-Signed TLS Certificate").severity).toBe("high");
  });

  it("recognises a self-signed leaf even when OpenSSL reported a different first error", () => {
    const r = healthy({ trusted: false, trustError: "CERT_HAS_EXPIRED", certificate: goodCert({ selfSigned: true, notAfter: daysFromNow(-2) }) });
    expect(names(r)).toEqual(["TLS Certificate Expired", "Self-Signed TLS Certificate"]);
  });

  it("does not call a self-signed certificate untrusted when the scanner's trust store holds it", () => {
    expect(names(healthy({ trusted: true, certificate: goodCert({ selfSigned: true }) }))).toEqual([]);
  });

  it("high 'not trusted' for a chain that ends in an unknown root, with OpenSSL's code as evidence", () => {
    const r = healthy({ trusted: false, trustError: "SELF_SIGNED_CERT_IN_CHAIN" });
    expect(names(r)).toEqual(["TLS Certificate Not Trusted"]);
    expect(one(r, "TLS Certificate Not Trusted").evidence).toContain("SELF_SIGNED_CERT_IN_CHAIN");
    expect(one(r, "TLS Certificate Not Trusted").severity).toBe("high");
  });

  it("medium 'chain incomplete' when only the leaf was sent", () => {
    const r = healthy({ trusted: false, trustError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" });
    expect(names(r)).toEqual(["TLS Certificate Chain Incomplete"]);
    expect(one(r, "TLS Certificate Chain Incomplete").severity).toBe("medium");
  });

  it("leaves expiry and hostname problems to their own findings rather than adding a trust finding", () => {
    expect(names(healthy({ trusted: false, trustError: "CERT_HAS_EXPIRED", certificate: goodCert({ notAfter: daysFromNow(-1) }) }))).toEqual(["TLS Certificate Expired"]);
    expect(names(healthy({ trusted: false, trustError: "ERR_TLS_CERT_ALTNAME_INVALID", certificate: goodCert({ hostnameMatches: false }) }))).toEqual(["TLS Certificate Does Not Match the Hostname"]);
  });

  it("does not report trust when no certificate could be read", () => {
    expect(tlsFindings(healthy({ certificate: null, trusted: false, trustError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }), NOW)).toEqual([]);
  });
});
