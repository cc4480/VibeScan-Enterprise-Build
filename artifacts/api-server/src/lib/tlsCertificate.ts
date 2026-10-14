/**
 * Reading the peer certificate: the signature algorithm (from the DER, which node does not expose), the key
 * and its size, and the dates and names. Split from tlsCheck.ts, which re-exports both functions.
 */
import * as tls from "node:tls";
import { X509Certificate } from "node:crypto";
import type { TlsCertificate } from "./tlsCheckTypes";

// ── The certificate ──────────────────────────────────────────────────────────

const SIGNATURE_OIDS: Record<string, string> = {
  "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
  "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.10": "RSASSA-PSS",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
  "1.2.840.10045.4.1": "ecdsa-with-SHA1",
  "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.2.840.10040.4.3": "dsaWithSHA1",
  "2.16.840.1.101.3.4.3.2": "dsa-with-SHA256",
  "1.3.14.3.2.3": "md5WithRSA",
  "1.3.14.3.2.29": "sha1WithRSA",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
};

/** One DER element: its tag and where its content starts and ends. Null when the bytes are not valid DER. */
function readTlv(buf: Uint8Array, pos: number): { tag: number; start: number; end: number } | null {
  if (pos + 2 > buf.length) return null;
  const tag = buf[pos]!;
  let len = buf[pos + 1]!;
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i]!;
    start += n;
  }
  const end = start + len;
  return end > buf.length ? null : { tag, start, end };
}

function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const parts: number[] = [Math.floor(bytes[0]! / 40), bytes[0]! % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i]! & 0x7f);
    if (!(bytes[i]! & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

/**
 * The signature algorithm of a DER certificate, read from the outer SEQUENCE
 * { tbsCertificate, signatureAlgorithm, signatureValue }. Node does not expose it. Returns the OpenSSL
 * name when known, the dotted OID otherwise, and null when the bytes are not a certificate.
 */
export function signatureAlgorithmOf(der: Uint8Array): string | null {
  const cert = readTlv(der, 0);
  if (!cert || cert.tag !== 0x30) return null;
  const tbs = readTlv(der, cert.start);
  if (!tbs || tbs.tag !== 0x30) return null;
  const alg = readTlv(der, tbs.end);
  if (!alg || alg.tag !== 0x30) return null;
  const oid = readTlv(der, alg.start);
  if (!oid || oid.tag !== 0x06) return null;
  const dotted = decodeOid(der.subarray(oid.start, oid.end));
  return SIGNATURE_OIDS[dotted] ?? (dotted || null);
}

const KEY_TYPES: Record<string, string> = { rsa: "RSA", "rsa-pss": "RSA-PSS", dsa: "DSA", ec: "EC", ed25519: "Ed25519", ed448: "Ed448" };

const EC_BITS: Record<string, number> = { prime256v1: 256, secp256k1: 256, secp384r1: 384, secp521r1: 521, secp224r1: 224, prime192v1: 192 };

const text = (v: string | string[] | undefined): string | null => (Array.isArray(v) ? v[0] : v) || null;

/** The leaf certificate as the report needs it. Null when the server presented nothing Node could read. */
export function describeCertificate(host: string, peer: tls.PeerCertificate): TlsCertificate | null {
  if (!peer || !peer.raw || peer.raw.length === 0) return null;

  let mismatch: Error | undefined;
  try {
    mismatch = tls.checkServerIdentity(host, peer);
  } catch (err) {
    mismatch = err instanceof Error ? err : new Error(String(err));
  }

  let x509: X509Certificate | null = null;
  try {
    x509 = new X509Certificate(peer.raw);
  } catch {
    x509 = null;
  }

  let keyType: string | null = null;
  let keyBits: number | null = typeof peer.bits === "number" ? peer.bits : null;
  let selfSigned = false;
  if (x509) {
    try {
      const key = x509.publicKey;
      keyType = KEY_TYPES[key.asymmetricKeyType ?? ""] ?? key.asymmetricKeyType ?? null;
      const d = key.asymmetricKeyDetails;
      if (keyBits === null) keyBits = d?.modulusLength ?? (d?.namedCurve ? (EC_BITS[d.namedCurve] ?? null) : null);
    } catch {
      /* the key stays unknown */
    }
    try {
      selfSigned = x509.checkIssued(x509) && x509.verify(x509.publicKey);
    } catch {
      selfSigned = false;
    }
  }

  const iso = (s: string | undefined): string | null => {
    const t = s ? Date.parse(s) : NaN;
    return Number.isNaN(t) ? null : new Date(t).toISOString();
  };
  const sans = (peer.subjectaltname ?? "")
    .split(/,\s*/)
    .map((s) => s.replace(/^(?:DNS|IP Address):/i, "").trim())
    .filter(Boolean);

  return {
    subject: text(peer.subject?.CN) ?? text(peer.subject?.O),
    issuer: text(peer.issuer?.CN) ?? text(peer.issuer?.O),
    notBefore: iso(peer.valid_from),
    notAfter: iso(peer.valid_to),
    subjectAltNames: sans,
    hostnameMatches: mismatch === undefined,
    hostnameError: mismatch ? mismatch.message.slice(0, 200) : null,
    selfSigned,
    keyType,
    keyBits,
    signatureAlgorithm: signatureAlgorithmOf(peer.raw),
  };
}
