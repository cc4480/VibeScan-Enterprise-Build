/** Constants and small helpers the TLS findings share: certificate dates, wording, and the weak-cipher tests. */
import { type TlsCertificate, type TlsHandshakeResult, type TlsVersion } from "./tlsCheckTypes";

export const DAY_MS = 86_400_000;

/** A certificate with fewer days than this left is reported, at low severity. */
export const EXPIRY_WARNING_DAYS = 14;

/**
 * How close to expiry a certificate must be before it is reported. ACME clients renew once a third of
 * the lifetime is left, so the window is that third, capped at EXPIRY_WARNING_DAYS. A 90-day
 * certificate is judged exactly as before; a short-lived one (Let's Encrypt issues 6-day certificates)
 * always sat inside the fixed window and was reported as failing renewal on every scan.
 */
export function expiryWarningMs(cert: TlsCertificate): number {
  const from = cert.notBefore ? Date.parse(cert.notBefore) : NaN;
  const to = cert.notAfter ? Date.parse(cert.notAfter) : NaN;
  const lifetime = !Number.isNaN(from) && !Number.isNaN(to) && from < to ? to - from : Infinity;
  return Math.min(EXPIRY_WARNING_DAYS * DAY_MS, lifetime / 3);
}


/** Certificate problems that are reported by their own finding, so the trust finding stays out of their way. */
export const REPORTED_SEPARATELY = new Set(["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "ERR_TLS_CERT_ALTNAME_INVALID"]);

/** The OpenSSL code for "the server sent only its own certificate and it is not self-signed". */
export const LEAF_ONLY = "UNABLE_TO_VERIFY_LEAF_SIGNATURE";

export const LEGACY: readonly TlsVersion[] = ["TLSv1", "TLSv1.1"];

export type CertificateState =
  | { state: "expired"; days: number }
  | { state: "not-yet-valid"; days: number }
  | { state: "valid"; days: number }
  | { state: "unknown" };

/**
 * Where a certificate stands against the clock. `days` is whole days: how long ago it expired (0 when
 * it lapsed today), how long until it becomes valid, or how many are left (rounded down, so "13" means
 * under 14).
 */
export function certificateState(cert: TlsCertificate | null, now: Date = new Date()): CertificateState {
  if (!cert) return { state: "unknown" };
  const from = cert.notBefore ? Date.parse(cert.notBefore) : NaN;
  const to = cert.notAfter ? Date.parse(cert.notAfter) : NaN;
  if (Number.isNaN(to) && Number.isNaN(from)) return { state: "unknown" };
  const t = now.getTime();
  if (!Number.isNaN(from) && t < from) return { state: "not-yet-valid", days: Math.ceil((from - t) / DAY_MS) };
  if (!Number.isNaN(to) && t > to) return { state: "expired", days: Math.floor((t - to) / DAY_MS) };
  if (!Number.isNaN(to)) return { state: "valid", days: Math.floor((to - t) / DAY_MS) };
  return { state: "unknown" };
}

export const hostPort = (r: TlsHandshakeResult) => `${r.host}:${r.port}`;

export const days = (n: number) => `${n} day${n === 1 ? "" : "s"}`;
/** "3 days ago", or "less than a day ago" for a certificate that lapsed within the last 24 hours. */
export const ago = (n: number) => (n === 0 ? "less than a day ago" : `${days(n)} ago`);

export function certLines(cert: TlsCertificate): string[] {
  return [
    cert.subject ? `Subject: ${cert.subject}` : null,
    cert.issuer ? `Issuer: ${cert.issuer}` : null,
    cert.notBefore ? `Valid from: ${cert.notBefore}` : null,
    cert.notAfter ? `Valid to: ${cert.notAfter}` : null,
  ].filter((l): l is string => l !== null);
}

/** RC4, DES/3DES, NULL, export-grade, anonymous and MD5-based suites. */
export const WEAK_CIPHER = /RC4|3DES|\bDES\b|DES-CBC|DES_CBC|\bNULL\b|-NULL-|_NULL_|EXPORT|\bEXP-|anon|\bADH\b|\bAECDH\b|ADH-|AECDH-|[-_]MD5\b/i;

/** A suite's key exchange is ephemeral when its name says ECDHE or DHE. TLS 1.3 suites always are. */
export function isForwardSecret(protocol: TlsVersion, cipher: string, standardName: string | null): boolean {
  if (protocol === "TLSv1.3") return true;
  return /^(?:ECDHE|DHE|EDH)[-_]/i.test(cipher) || /^TLS_(?:ECDHE|DHE)_/i.test(standardName ?? "");
}

export const WEAK_HASH = /md[245]|sha-?1(?!\d)/i;

