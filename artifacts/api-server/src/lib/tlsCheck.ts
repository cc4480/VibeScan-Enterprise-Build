/**
 * The scanner's own TLS configuration check, using node:tls.
 *
 * It replaces the Qualys SSL Labs assessment as the default (that service's terms require permission
 * for commercial use; see ssllabs.ts). It connects to the target's host:443 (or the port in its URL)
 * and reports what the handshake shows: the protocol versions the server accepts, the cipher suite it
 * chooses, and its certificate (validity, hostname, chain trust, key size, signature algorithm). It
 * grades nothing and claims no third party's grade; tlsCheckFindings.ts turns the observations into
 * findings.
 *
 * Safety. The scanner's rules for outbound connections apply here too: a private or local target is
 * refused (unless the operator opted in with ALLOW_PRIVATE_SCAN_TARGETS), and every socket resolves
 * its name through vettedLookup, so the address that is judged is the address that is connected to
 * and a DNS answer that changes between connections cannot lead the check inside the network. An IP
 * literal never reaches the resolver, so it is judged here before any socket opens. Every handshake
 * has a hard timeout.
 *
 * Probing. One handshake per protocol version, each pinned to exactly that version (min = max), run
 * in parallel. The highest version that completes is what a current client gets, and its certificate
 * and cipher are the ones reported. Verification is off during the probe (rejectUnauthorized: false)
 * so a broken certificate can still be read; trust is then taken from the socket's own verdict.
 * TLS 1.0 and 1.1 are best-effort: the scanner's OpenSSL refuses to offer them at its default
 * security level, so those probes lower the level for the probe only, and when the library still
 * will not offer them the answer is "untested", never "not supported". SSL 2.0 and 3.0 cannot be
 * spoken by this library and are not tested.
 */
import * as net from "node:net";
import * as tls from "node:tls";
import { X509Certificate } from "node:crypto";
import { vettedLookup } from "./pinnedDispatcher";
import { isHostnameSafeSync, privateTargetsAllowed } from "./ssrfGuard";
import {
  TLS_LABEL,
  TLS_VERSIONS,
  type ProtocolProbe,
  type TlsCertificate,
  type TlsHandshakeResult,
  type TlsInspection,
  type TlsVersion,
} from "./tlsCheckTypes";

/** Per handshake: connect, TLS negotiation and certificate read must finish within this. */
export const TLS_CONNECT_TIMEOUT_MS = 8_000;

/**
 * Cipher string for the legacy probes. OpenSSL 3 disables TLS 1.0 and 1.1 at security level 1 and
 * above, and Node's default is level 1, so without this the library fails before sending anything.
 * It loosens only what this probe's client side will accept; it does not touch the server.
 */
const LEGACY_CIPHERS = "DEFAULT:@SECLEVEL=0";

const REFUSED_ADDRESS = "the address is private or local, which the scanner will not connect to";

// ── Classifying a failed handshake ───────────────────────────────────────────

export type HandshakeFailure =
  /** vettedLookup refused the address. */
  | "blocked"
  /** The scanner's own TLS library would not offer the version (nothing was sent). */
  | "local"
  /** The server's certificate or key is below the client's security level; a lower level can still read it. */
  | "security-level"
  /** The server answered and refused: a protocol alert, or a reply naming another version. */
  | "refused"
  /** The connection was closed or reset without an alert. Ambiguous: not evidence either way. */
  | "closed"
  /** Timeout, refused connection, DNS failure. */
  | "network";

const LOCAL_CODES = new Set([
  "ERR_SSL_NO_PROTOCOLS_AVAILABLE",
  "ERR_SSL_NO_CIPHERS_AVAILABLE",
  "ERR_SSL_NO_SUITABLE_DIGEST_ALGORITHM",
  "ERR_TLS_INVALID_PROTOCOL_VERSION",
  "ERR_TLS_PROTOCOL_VERSION_CONFLICT",
]);

const CLOSED_CODES = new Set(["ECONNRESET", "EPIPE", "ERR_SSL_UNEXPECTED_EOF_WHILE_READING"]);

/** Reads a Node TLS error into what it says about the server. Exported for tests. */
export function classifyHandshakeError(err: { code?: string; reason?: string; message?: string }): HandshakeFailure {
  const code = err.code ?? "";
  const text = `${err.reason ?? ""} ${err.message ?? ""}`.toLowerCase();
  if (code === "ESSRFBLOCKED") return "blocked";
  if (/(?:key|md|dh key) too (?:small|weak)/.test(text) || /^ERR_SSL_(?:EE|CA|DH)_.*(?:TOO_SMALL|TOO_WEAK)/.test(code)) return "security-level";
  if (LOCAL_CODES.has(code) || /no protocols available|no ciphers available/.test(text)) return "local";
  if (CLOSED_CODES.has(code) || /disconnected before secure tls|socket hang up/.test(text)) return "closed";
  if (code.startsWith("ERR_SSL_") || /\balert\b/.test(text)) return "refused";
  return "network";
}

/** One line for a person: OpenSSL's reason when it gave one, else Node's code, else the message. */
function describeError(err: { code?: string; reason?: string; message?: string }): string {
  const first = (err.reason || err.message || err.code || "unknown error").split("\n")[0]!.trim();
  return first.length > 140 ? `${first.slice(0, 137)}...` : first;
}

// ── One handshake ────────────────────────────────────────────────────────────

interface Handshake {
  cipher: { name: string; standardName: string | null };
  authorized: boolean;
  authorizationError: string | null;
  peer: tls.PeerCertificate;
}

type Attempt =
  | { ok: true; handshake: Handshake }
  | { ok: false; failure: HandshakeFailure; reason: string };

function failure(err: unknown, timedOutMs?: number): Attempt {
  if (timedOutMs !== undefined) {
    return { ok: false, failure: "network", reason: `timed out after ${timedOutMs >= 1000 ? `${Math.round(timedOutMs / 1000)}s` : `${timedOutMs} ms`}` };
  }
  const e = (err ?? {}) as { code?: string; reason?: string; message?: string };
  return { ok: false, failure: classifyHandshakeError(e), reason: describeError(e) };
}

function attempt(o: { host: string; port: number; version: TlsVersion; ciphers?: string; timeoutMs: number }): Promise<Attempt> {
  return new Promise<Attempt>((resolve) => {
    let settled = false;
    let socket: tls.TLSSocket | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const done = (a: Attempt) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket?.destroy();
      resolve(a);
    };
    timer = setTimeout(() => done(failure(null, o.timeoutMs)), o.timeoutMs);
    try {
      socket = tls.connect(
        {
          host: o.host,
          port: o.port,
          // SNI is a hostname; an IP literal has none.
          ...(net.isIP(o.host) ? {} : { servername: o.host }),
          minVersion: o.version,
          maxVersion: o.version,
          ...(o.ciphers ? { ciphers: o.ciphers } : {}),
          // On purpose: an expired, self-signed or mismatched certificate is what this check reports,
          // so it must be able to finish the handshake and read it. Trust is judged below.
          rejectUnauthorized: false,
          lookup: vettedLookup as never,
        },
        () => {
          try {
            const c = socket!.getCipher();
            const authErr = socket!.authorizationError as unknown;
            done({
              ok: true,
              handshake: {
                cipher: { name: c?.name ?? "unknown", standardName: c?.standardName ?? null },
                authorized: socket!.authorized,
                authorizationError: authErr == null ? null : typeof authErr === "string" ? authErr : ((authErr as { code?: string }).code ?? String(authErr)),
                peer: socket!.getPeerCertificate(),
              },
            });
          } catch (err) {
            done(failure(err));
          }
        },
      );
      socket.on("error", (err) => done(failure(err)));
    } catch (err) {
      done(failure(err));
    }
  });
}

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

// ── One protocol version ─────────────────────────────────────────────────────

interface VersionOutcome {
  version: TlsVersion;
  probe: ProtocolProbe;
  handshake?: Handshake;
  failure?: HandshakeFailure;
}

const isLegacy = (v: TlsVersion) => v === "TLSv1" || v === "TLSv1.1";

async function probeVersion(host: string, port: number, version: TlsVersion, timeoutMs: number): Promise<VersionOutcome> {
  // The legacy versions need the lowered security level from the start. The modern ones try the
  // default first, and only a certificate the client's level refuses (a 1024-bit key, a SHA-1
  // signature) is retried lower, so that it can still be read and reported.
  let result = await attempt({ host, port, version, timeoutMs, ...(isLegacy(version) ? { ciphers: LEGACY_CIPHERS } : {}) });
  if (!result.ok && result.failure === "security-level" && !isLegacy(version)) {
    result = await attempt({ host, port, version, timeoutMs, ciphers: LEGACY_CIPHERS });
  }
  if (result.ok) {
    const { name, standardName } = result.handshake.cipher;
    return { version, handshake: result.handshake, probe: { status: "accepted", detail: standardName ?? name } };
  }
  const label = TLS_LABEL[version];
  switch (result.failure) {
    case "refused":
      return { version, failure: "refused", probe: { status: "rejected", detail: result.reason } };
    case "local":
      return { version, failure: "local", probe: { status: "untested", detail: `the scanner's TLS library would not offer ${label}` } };
    case "security-level":
      return { version, failure: "security-level", probe: { status: "untested", detail: "the server's certificate is below the scanner's minimum security level" } };
    case "closed":
      return { version, failure: "closed", probe: { status: "untested", detail: `the server closed the connection without an answer (${result.reason}); it most likely refuses ${label}, but that was not confirmed` } };
    default:
      return { version, failure: result.failure, probe: { status: "untested", detail: result.reason } };
  }
}

// ── The check ────────────────────────────────────────────────────────────────

/**
 * Inspect the TLS configuration of an https:// target. Never throws: every outcome, including
 * "nothing to inspect" and "could not connect", is a value.
 */
export async function inspectTls(targetUrl: string, opts: { timeoutMs?: number } = {}): Promise<TlsInspection> {
  const timeoutMs = opts.timeoutMs ?? TLS_CONNECT_TIMEOUT_MS;
  let url: URL;
  try {
    url = new URL(targetUrl);
  } catch {
    return { status: "skipped", reason: "the target is not a valid URL" };
  }
  if (url.protocol !== "https:") {
    return { status: "skipped", reason: "the target is not served over HTTPS, so there is no TLS to inspect" };
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, "").replace(/^\[(.+)\]$/, "$1");
  const port = url.port ? Number.parseInt(url.port, 10) : 443;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65_535) {
    return { status: "skipped", reason: "the target has no usable host and port" };
  }

  // An IP literal never goes through vettedLookup, so it is judged here, before any socket opens.
  // A name is judged by its shape here and by what it resolves to in vettedLookup, on every connection.
  if (!privateTargetsAllowed() && !isHostnameSafeSync(host)) {
    return { status: "skipped", reason: `refused: ${REFUSED_ADDRESS}` };
  }

  let outcomes: VersionOutcome[];
  try {
    outcomes = await Promise.all(TLS_VERSIONS.map((v) => probeVersion(host, port, v, timeoutMs)));
  } catch (err) {
    return { status: "failed", reason: describeError(err as Error) };
  }

  if (outcomes.some((o) => o.failure === "blocked")) {
    return { status: "skipped", reason: `refused: ${REFUSED_ADDRESS}` };
  }

  // TLS_VERSIONS is ascending, so the last accepted is the highest.
  const top = [...outcomes].reverse().find((o) => o.handshake);
  if (!top?.handshake) {
    if (outcomes.every((o) => o.failure === "network")) {
      return { status: "failed", reason: `could not connect to ${host}:${port}: ${outcomes[0]!.probe.detail ?? "no answer"}` };
    }
    const why = outcomes.map((o) => `${TLS_LABEL[o.version]}: ${o.probe.detail ?? o.probe.status}`).join("; ");
    return { status: "failed", reason: `no TLS handshake completed with ${host}:${port} (${why})` };
  }

  const protocols = Object.fromEntries(outcomes.map((o) => [o.version, o.probe])) as Record<TlsVersion, ProtocolProbe>;
  const h = top.handshake;
  const result: TlsHandshakeResult = {
    host,
    port,
    protocols,
    negotiated: { protocol: top.version, cipher: h.cipher.name, standardName: h.cipher.standardName },
    certificate: describeCertificate(host, h.peer),
    trusted: h.authorized,
    trustError: h.authorized ? null : h.authorizationError,
  };
  return { status: "inspected", result };
}
