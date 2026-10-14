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
import { TLS_LABEL, TLS_VERSIONS, type TlsHandshakeResult } from "./tlsCheckTypes";
import { LEGACY, WEAK_CIPHER, hostPort, ago, certificateState, isForwardSecret } from "./tlsCheckShared";
import { certificateFindings } from "./tlsCheckCertFindings";

// The shared pieces live in tlsCheckShared.ts; re-exported so every import path is unchanged.
export { EXPIRY_WARNING_DAYS, expiryWarningMs, certificateState, type CertificateState } from "./tlsCheckShared";

/** What the handshake showed that is worth reporting. Order is stable: protocols, certificate, trust, cipher. */
export function tlsFindings(r: TlsHandshakeResult, now: Date = new Date()): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];
  const target = hostPort(r);

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

  // Certificate validity, host match, chain trust, key size and signature (tlsCheckCertFindings.ts).
  certificateFindings(findings, r, now);

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
