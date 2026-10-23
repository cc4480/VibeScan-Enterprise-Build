/**
 * Shapes for the in-house TLS configuration check (tlsCheck.ts). Plain data only, so the finding
 * logic (tlsCheckFindings.ts) can be driven by an object literal in a test, with no socket.
 */

/** The protocol versions the check probes, in the names Node uses. */
export const TLS_VERSIONS = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"] as const;
export type TlsVersion = (typeof TLS_VERSIONS)[number];

/** How a version reads in a report. */
export const TLS_LABEL: Record<TlsVersion, string> = {
  "TLSv1": "TLS 1.0",
  "TLSv1.1": "TLS 1.1",
  "TLSv1.2": "TLS 1.2",
  "TLSv1.3": "TLS 1.3",
};

/**
 * What the probe for one version learned.
 *   accepted  a handshake pinned to exactly this version completed.
 *   rejected  the server answered and refused it (a protocol alert, or a reply naming another version).
 *   untested  nothing can be said: the scanner's own TLS library would not offer the version, the
 *             server dropped the connection without an alert, or the network failed. Never read this
 *             as "not supported".
 */
export interface ProtocolProbe {
  status: "accepted" | "rejected" | "untested";
  /** accepted: the cipher suite used. rejected: how the server refused. untested: why it could not be tested. */
  detail?: string;
}

/** What the certificate the server presented says, read from its leaf certificate. */
export interface TlsCertificate {
  /** The certificate's common name (or its full subject when it has none). */
  subject: string | null;
  /** The issuer's common name, or organisation when it has none. */
  issuer: string | null;
  /** ISO 8601. */
  notBefore: string | null;
  notAfter: string | null;
  subjectAltNames: string[];
  /** Whether the certificate covers the host the check connected to. */
  hostnameMatches: boolean;
  /** Node's reason when it does not. */
  hostnameError: string | null;
  /** The leaf is signed by its own key. */
  selfSigned: boolean;
  /** "RSA", "EC", "Ed25519" and so on, when it could be read. */
  keyType: string | null;
  /** RSA modulus length, or the size of the EC curve. */
  keyBits: number | null;
  /** The OpenSSL name of the certificate's signature algorithm, or its dotted OID when unnamed. */
  signatureAlgorithm: string | null;
}

/** What one successful probe handed back. */
export interface TlsHandshakeResult {
  host: string;
  port: number;
  protocols: Record<TlsVersion, ProtocolProbe>;
  /** What a current client gets: the highest version that completed, and the suite it chose. Null when none did. */
  negotiated: { protocol: TlsVersion; cipher: string; standardName: string | null } | null;
  /** From the same handshake. Null when the server presented no certificate Node could read. */
  certificate: TlsCertificate | null;
  /**
   * Whether the chain validates against the root certificates bundled with the scanner's runtime.
   * The check connects with verification off so it can still inspect a bad certificate, then
   * reads this from the socket's own verdict.
   */
  trusted: boolean;
  /** OpenSSL's code when it is not trusted (DEPTH_ZERO_SELF_SIGNED_CERT, CERT_HAS_EXPIRED, ...). */
  trustError: string | null;
}

/** The check's outcome, including the cases where there is nothing to inspect. */
export type TlsInspection =
  | { status: "inspected"; result: TlsHandshakeResult }
  /** Not run on purpose: the target is not HTTPS, or its address is one the scanner will not connect to. */
  | { status: "skipped"; reason: string }
  /** Tried and could not complete a handshake at all. */
  | { status: "failed"; reason: string };
