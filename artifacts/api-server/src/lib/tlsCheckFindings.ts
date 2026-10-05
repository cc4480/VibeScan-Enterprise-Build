/**
 * Turns what the TLS check observed (tlsCheck.ts) into findings and a plain-language summary.
 *
 * Pure: a handshake result in, findings out, so every rule is tested with an object literal and no
 * socket. Nothing here grades the server with a letter. A finding is raised only for something the
 * handshake positively showed, and a protocol the scanner could not test is reported as untested,
 * never as "not supported".
 *
 * Each finding opens its evidence with a long fixed sentence. The finding fingerprint (fingerprint.ts)
 * keeps the first 50 characters of the evidence, so a day count or a date that changes between two
 * scans of the same server must not fall inside them, or a dismissed finding would come back.
 */
import { vuln, type ScanVulnerability } from "./scannerTypes";
import { TLS_LABEL, TLS_VERSIONS, type TlsCertificate, type TlsHandshakeResult, type TlsVersion } from "./tlsCheckTypes";

const DAY_MS = 86_400_000;

/** A certificate with fewer days than this left is reported, at low severity. */
export const EXPIRY_WARNING_DAYS = 14;


/** Certificate problems that are reported by their own finding, so the trust finding stays out of their way. */
const REPORTED_SEPARATELY = new Set(["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "ERR_TLS_CERT_ALTNAME_INVALID"]);

/** The OpenSSL code for "the server sent only its own certificate and it is not self-signed". */
const LEAF_ONLY = "UNABLE_TO_VERIFY_LEAF_SIGNATURE";

const LEGACY: readonly TlsVersion[] = ["TLSv1", "TLSv1.1"];

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

const hostPort = (r: TlsHandshakeResult) => `${r.host}:${r.port}`;

const days = (n: number) => `${n} day${n === 1 ? "" : "s"}`;
/** "3 days ago", or "less than a day ago" for a certificate that lapsed within the last 24 hours. */
const ago = (n: number) => (n === 0 ? "less than a day ago" : `${days(n)} ago`);

function certLines(cert: TlsCertificate): string[] {
  return [
    cert.subject ? `Subject: ${cert.subject}` : null,
    cert.issuer ? `Issuer: ${cert.issuer}` : null,
    cert.notBefore ? `Valid from: ${cert.notBefore}` : null,
    cert.notAfter ? `Valid to: ${cert.notAfter}` : null,
  ].filter((l): l is string => l !== null);
}

/** RC4, DES/3DES, NULL, export-grade, anonymous and MD5-based suites. */
const WEAK_CIPHER = /RC4|3DES|\bDES\b|DES-CBC|DES_CBC|\bNULL\b|-NULL-|_NULL_|EXPORT|\bEXP-|anon|\bADH\b|\bAECDH\b|ADH-|AECDH-|[-_]MD5\b/i;

/** A suite's key exchange is ephemeral when its name says ECDHE or DHE. TLS 1.3 suites always are. */
function isForwardSecret(protocol: TlsVersion, cipher: string, standardName: string | null): boolean {
  if (protocol === "TLSv1.3") return true;
  return /^(?:ECDHE|DHE|EDH)[-_]/i.test(cipher) || /^TLS_(?:ECDHE|DHE)_/i.test(standardName ?? "");
}

const WEAK_HASH = /md[245]|sha-?1(?!\d)/i;

/** What the handshake showed that is worth reporting. Order is stable: protocols, certificate, trust, cipher. */
export function tlsFindings(r: TlsHandshakeResult, now: Date = new Date()): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];
  const target = hostPort(r);
  const cert = r.certificate;

  // ── Protocol versions ────────────────────────────────────────────────────
  const legacyAccepted = LEGACY.filter((v) => r.protocols[v]?.status === "accepted");
  if (legacyAccepted.length > 0) {
    const names = legacyAccepted.map((v) => TLS_LABEL[v]).join(" and ");
    findings.push(vuln({
      name: "Deprecated TLS Protocol Versions Accepted",
      severity: "medium",
      category: "Transport Security",
      description: `The server completed a handshake using ${names}. Both were deprecated by the IETF in RFC 8996 (2021) and are disabled in current browsers; they rely on cipher suites and a handshake design with known weaknesses (BEAST, Lucky13, weak MAC-then-encrypt constructions), and PCI DSS no longer accepts them. A client that can be talked into the older protocol can have its session downgraded to it.`,
      evidence: [
        "A handshake restricted to a deprecated TLS protocol version completed.",
        `Host: ${target}`,
        ...legacyAccepted.map((v) => `${TLS_LABEL[v]}: accepted${r.protocols[v].detail ? ` (${r.protocols[v].detail})` : ""}`),
        ...LEGACY.filter((v) => r.protocols[v]?.status === "untested").map((v) => `${TLS_LABEL[v]}: could not be tested${r.protocols[v].detail ? ` (${r.protocols[v].detail})` : ""}`),
      ].join("\n"),
      solution: "Allow only TLS 1.2 and TLS 1.3. nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3; HAProxy: ssl-min-ver TLSv1.2; on a managed load balancer or CDN, raise the minimum TLS version in its security policy. Mozilla's SSL Configuration Generator gives settings per server.",
      cweId: "CWE-326",
      cvssScore: 5.3,
      wstgId: "WSTG-CRYP-01",
      confidence: 95,
    }));
  }

  // ── Certificate validity ─────────────────────────────────────────────────
  const validity = certificateState(cert, now);
  if (cert && validity.state === "expired") {
    findings.push(vuln({
      name: "TLS Certificate Expired",
      severity: "high",
      category: "Transport Security",
      description: `The certificate the server presents expired ${ago(validity.days)}. Browsers block the site with a full-page warning, API clients and webhooks refuse the connection, and users who are trained to click through the warning are exposed to anyone who can intercept the connection.`,
      evidence: [
        "The certificate the server presented is past the end of its validity period.",
        `Host: ${target}`,
        ...certLines(cert),
        `Expired ${ago(validity.days)}`,
      ].join("\n"),
      solution: "Renew the certificate now and reload the server so it presents the new one. Automate renewal (certbot, acme.sh, or your host's managed certificates) and alert well before expiry; a renewed file that the running process has not re-read changes nothing.",
      cweId: "CWE-298",
      cvssScore: 7.4,
      wstgId: "WSTG-CRYP-01",
      confidence: 95,
    }));
  } else if (cert && validity.state === "not-yet-valid") {
    findings.push(vuln({
      name: "TLS Certificate Not Yet Valid",
      severity: "high",
      category: "Transport Security",
      description: `The certificate the server presents is not valid for another ${days(validity.days)}. Clients refuse it until then. This usually means a certificate was installed ahead of its start date, or the server's clock is wrong.`,
      evidence: [
        "The certificate the server presented has not reached the start of its validity period.",
        `Host: ${target}`,
        ...certLines(cert),
      ].join("\n"),
      solution: "Install a certificate that is already valid, and check that the server's clock is correct (NTP).",
      cweId: "CWE-298",
      cvssScore: 7.4,
      wstgId: "WSTG-CRYP-01",
      confidence: 90,
    }));
  } else if (cert && validity.state === "valid" && validity.days < EXPIRY_WARNING_DAYS) {
    findings.push(vuln({
      name: "TLS Certificate Expires Soon",
      severity: "low",
      category: "Transport Security",
      description: `The certificate the server presents expires in ${days(validity.days)} (the warning threshold is ${EXPIRY_WARNING_DAYS}). When it lapses the site fails for every visitor. Automatic renewal normally replaces a certificate well before this point, so a certificate this close to expiry suggests renewal is not working.`,
      evidence: [
        "The certificate the server presented is close to the end of its validity period.",
        `Host: ${target}`,
        ...certLines(cert),
        `${days(validity.days)} remaining`,
      ].join("\n"),
      solution: "Renew the certificate and reload the server, then find out why automatic renewal did not run (certbot timer, DNS or HTTP challenge failing, a deploy hook that does not reload the server).",
      cweId: "CWE-298",
      cvssScore: 3.1,
      wstgId: "WSTG-CRYP-01",
      confidence: 95,
    }));
  }

  // ── Certificate matches the host ─────────────────────────────────────────
  if (cert && !cert.hostnameMatches) {
    findings.push(vuln({
      name: "TLS Certificate Does Not Match the Hostname",
      severity: "high",
      category: "Transport Security",
      description: `The certificate the server presents does not list ${r.host}. Browsers refuse the connection with a name-mismatch warning, because a certificate for a different name proves nothing about who is behind this one. It usually means the wrong certificate is installed, a virtual host is missing its own certificate, or a wildcard does not cover the subdomain.`,
      evidence: [
        "The certificate the server presented does not cover the name that was requested.",
        `Host: ${target}`,
        cert.hostnameError ? `Reason: ${cert.hostnameError}` : null,
        cert.subject ? `Subject: ${cert.subject}` : null,
        cert.subjectAltNames.length > 0 ? `Names on the certificate: ${cert.subjectAltNames.slice(0, 20).join(", ")}${cert.subjectAltNames.length > 20 ? ", ..." : ""}` : "The certificate lists no subject alternative names.",
      ].filter((l): l is string => l !== null).join("\n"),
      solution: `Install a certificate that covers ${r.host} (list it in the subject alternative names), and make sure the server selects it for this name (SNI / the correct virtual host).`,
      cweId: "CWE-297",
      cvssScore: 7.4,
      wstgId: "WSTG-CRYP-01",
      confidence: 90,
    }));
  }

  // ── Chain trust ──────────────────────────────────────────────────────────
  if (!r.trusted && cert) {
    const code = r.trustError;
    const chainLines = [`Host: ${target}`, ...certLines(cert), code ? `Verification result (OpenSSL): ${code}` : null].filter((l): l is string => l !== null);
    if (cert.selfSigned || code === "DEPTH_ZERO_SELF_SIGNED_CERT") {
      findings.push(vuln({
        name: "Self-Signed TLS Certificate",
        severity: "high",
        category: "Transport Security",
        description: "The certificate the server presents is signed by its own key rather than by a certificate authority. Browsers show a full-page warning and API clients refuse the connection. Anyone who clicks through, or any client that turns verification off, gets no proof of who is on the other end, so an attacker on the path can impersonate the site.",
        evidence: ["The certificate the server presented vouches for itself and chains to no trusted authority.", ...chainLines].join("\n"),
        solution: "Install a certificate from a public certificate authority (Let's Encrypt issues them free and renews them automatically) and serve the full chain. For an internal service, issue the certificate from your own CA and install that CA on the clients instead of clicking through warnings.",
        cweId: "CWE-295",
        cvssScore: 7.4,
        wstgId: "WSTG-CRYP-01",
        confidence: 90,
      }));
    } else if (code === LEAF_ONLY) {
      findings.push(vuln({
        name: "TLS Certificate Chain Incomplete",
        severity: "medium",
        category: "Transport Security",
        description: "The server sent only its own certificate, not the intermediate certificate(s) that connect it to a trusted root, so the chain could not be verified. Some browsers fetch the missing intermediate on their own, which hides the fault, but curl, Node, Java, Python and most mobile and server-to-server clients fail the connection. (A certificate from a private CA presents the same way.)",
        evidence: ["The server presented a certificate that could not be linked to a trusted root.", ...chainLines].join("\n"),
        solution: "Serve the full chain: the certificate followed by the CA's intermediate certificate(s). With certbot use fullchain.pem rather than cert.pem; with nginx, ssl_certificate must point at the combined file; on a managed host, upload the intermediate bundle too.",
        cweId: "CWE-295",
        cvssScore: 5.3,
        wstgId: "WSTG-CRYP-01",
        confidence: 85,
      }));
    } else if (!code || !REPORTED_SEPARATELY.has(code)) {
      findings.push(vuln({
        name: "TLS Certificate Not Trusted",
        severity: "high",
        category: "Transport Security",
        description: `The certificate chain the server presents does not lead to a root certificate that the scanner trusts${code ? ` (OpenSSL reported ${code})` : ""}. Clients that verify certificates will refuse the connection, and users are told the site is not secure. The scanner judges the chain against the root certificates bundled with its own runtime, so a certificate from a private CA reads the same way; if that is intended, the clients must be configured to trust that CA.`,
        evidence: ["The certificate chain the server presented does not validate against the scanner's trusted roots.", ...chainLines].join("\n"),
        solution: "Serve a certificate issued by a publicly trusted certificate authority together with its intermediates. If the CA is private by design, install that CA on every client rather than disabling verification.",
        cweId: "CWE-295",
        cvssScore: 7.4,
        wstgId: "WSTG-CRYP-01",
        confidence: 80,
      }));
    }
  }

  // ── Key size and signature ───────────────────────────────────────────────
  if (cert && cert.keyBits !== null && cert.keyType) {
    const short = cert.keyType === "EC" ? cert.keyBits < 224 : /^(?:RSA|RSA-PSS|DSA)$/i.test(cert.keyType) ? cert.keyBits < 2048 : false;
    if (short) {
      findings.push(vuln({
        name: "TLS Certificate Key Too Short",
        severity: "medium",
        category: "Transport Security",
        description: `The certificate's ${cert.keyType} key is ${cert.keyBits} bits, below the ${cert.keyType === "EC" ? "224-bit" : "2048-bit"} minimum that NIST and the CA/Browser Forum require. A key this size is within reach of a well-funded attacker, and anyone who recovers it can impersonate the site.`,
        evidence: [
          "The certificate the server presented uses a public key below the accepted minimum size.",
          `Host: ${target}`,
          `Key: ${cert.keyType} ${cert.keyBits} bits`,
        ].join("\n"),
        solution: cert.keyType === "EC" ? "Reissue the certificate with a P-256 or P-384 key." : "Reissue the certificate with an RSA key of at least 2048 bits (3072 for long-lived keys), or with an ECDSA P-256 key.",
        cweId: "CWE-326",
        cvssScore: 5.9,
        wstgId: "WSTG-CRYP-01",
        confidence: 90,
      }));
    }
  }
  if (cert?.signatureAlgorithm && WEAK_HASH.test(cert.signatureAlgorithm)) {
    findings.push(vuln({
      name: "TLS Certificate Signed With a Weak Hash",
      severity: "medium",
      category: "Transport Security",
      description: `The server's certificate is signed with ${cert.signatureAlgorithm}. MD5 and SHA-1 signatures can be forged by finding hash collisions, which has been practical for MD5 since 2008 and for SHA-1 since 2017. Browsers stopped accepting SHA-1 certificates in 2017, and recent OpenSSL builds refuse them by default.`,
      evidence: [
        "The certificate the server presented is signed with a hash function that has known collision attacks.",
        `Host: ${target}`,
        `Signature algorithm: ${cert.signatureAlgorithm}`,
      ].join("\n"),
      solution: "Reissue the certificate so it is signed with SHA-256 or stronger (any current CA does this by default).",
      cweId: "CWE-328",
      cvssScore: 5.9,
      wstgId: "WSTG-CRYP-01",
      confidence: 90,
    }));
  }

  // ── The cipher suite a current client gets ───────────────────────────────
  const n = r.negotiated;
  if (n) {
    const suite = n.standardName ? `${n.cipher} (${n.standardName})` : n.cipher;
    if (WEAK_CIPHER.test(n.cipher) || WEAK_CIPHER.test(n.standardName ?? "")) {
      findings.push(vuln({
        name: "Weak Cipher Suite Negotiated",
        severity: "medium",
        category: "Transport Security",
        description: `The server chose ${suite}, which relies on a broken or obsolete primitive (RC4, DES/3DES, a NULL or EXPORT cipher, anonymous key exchange or MD5). Traffic protected by it can be decrypted or tampered with by a capable attacker.`,
        evidence: [
          "The server chose a cipher suite built on a broken or obsolete primitive.",
          `Host: ${target}`,
          `Protocol: ${TLS_LABEL[n.protocol]}`,
          `Cipher suite: ${suite}`,
        ].join("\n"),
        solution: "Remove RC4, DES/3DES, NULL, EXPORT, anonymous and MD5 suites from the server's cipher list and prefer AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE key exchange.",
        cweId: "CWE-327",
        cvssScore: 5.9,
        wstgId: "WSTG-CRYP-01",
        confidence: 90,
      }));
    } else if (!isForwardSecret(n.protocol, n.cipher, n.standardName)) {
      findings.push(vuln({
        name: "Cipher Suite Without Forward Secrecy",
        severity: "low",
        category: "Transport Security",
        description: `The scanner offered forward-secret (ECDHE) suites and the server still chose ${suite}, which uses a static RSA key exchange. Without forward secrecy, anyone who records traffic today and obtains the server's private key later can decrypt all of it.`,
        evidence: [
          "The server chose a cipher suite whose key exchange is not ephemeral.",
          `Host: ${target}`,
          `Protocol: ${TLS_LABEL[n.protocol]}`,
          `Cipher suite: ${suite}`,
        ].join("\n"),
        solution: "Enable ECDHE suites and put them first in the server's cipher preference, or enable TLS 1.3, whose suites are all forward-secret. Mozilla's SSL Configuration Generator gives a ready list.",
        cweId: "CWE-326",
        cvssScore: 3.7,
        wstgId: "WSTG-CRYP-01",
        confidence: 85,
      }));
    }
  }

  return findings;
}

function protocolList(r: TlsHandshakeResult, status: "accepted" | "rejected" | "untested"): string {
  return TLS_VERSIONS.filter((v) => r.protocols[v]?.status === status).map((v) => TLS_LABEL[v]).join(", ");
}

/** One short phrase for the certificate's standing, e.g. "certificate valid for 87 more days". */
function certificatePhrase(r: TlsHandshakeResult, now: Date): string {
  const v = certificateState(r.certificate, now);
  switch (v.state) {
    case "expired": return `certificate expired ${ago(v.days)}`;
    case "not-yet-valid": return "certificate not yet valid";
    case "valid": return `certificate valid for ${v.days} more day${v.days === 1 ? "" : "s"}`;
    default: return "certificate could not be read";
  }
}

/**
 * A few words for the test record, e.g. "TLS 1.3, certificate valid for 87 more days". No letter,
 * no score: it says what was observed.
 */
export function tlsHeadline(r: TlsHandshakeResult, now: Date = new Date()): string {
  const n = r.negotiated ? `${TLS_LABEL[r.negotiated.protocol]} negotiated` : "no protocol negotiated";
  return `${n}, ${certificatePhrase(r, now)}`;
}

/**
 * The check's result in plain sentences. What a reader would want if they asked "what does this
 * server's TLS look like?", with the untestable parts marked as untested.
 */
export function tlsSummary(r: TlsHandshakeResult, now: Date = new Date()): string {
  const lines: string[] = [];
  lines.push(r.negotiated
    ? `${hostPort(r)} negotiated ${TLS_LABEL[r.negotiated.protocol]} with ${r.negotiated.standardName ?? r.negotiated.cipher}.`
    : `${hostPort(r)} completed no handshake.`);

  const accepted = protocolList(r, "accepted");
  const rejected = protocolList(r, "rejected");
  const untested = protocolList(r, "untested");
  lines.push(`Protocol versions accepted: ${accepted || "none"}.`);
  if (rejected) lines.push(`Refused by the server: ${rejected}.`);
  if (untested) lines.push(`Could not test (the scanner could not establish an answer, which does not mean the server refuses them): ${untested}.`);

  const cert = r.certificate;
  if (cert) {
    const parts = [
      certificatePhrase(r, now),
      r.trusted ? "chain trusted" : `chain not trusted${r.trustError ? ` (${r.trustError})` : ""}`,
      cert.hostnameMatches ? "name matches" : "name does not match",
      cert.keyType && cert.keyBits ? `${cert.keyType} ${cert.keyBits}-bit key` : null,
      cert.signatureAlgorithm ? `signed with ${cert.signatureAlgorithm}` : null,
    ].filter((p): p is string => p !== null);
    lines.push(`Certificate: ${parts.join("; ")}.`);
  } else {
    lines.push("No certificate could be read.");
  }
  lines.push("SSL 2.0 and SSL 3.0 are not tested; the scanner's TLS library cannot speak them.");
  return lines.join(" ");
}
