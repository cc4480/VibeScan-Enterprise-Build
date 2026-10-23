/**
 * The findings about the certificate the server presented: validity and expiry, whether it covers the host,
 * whether the chain is trusted, and the key and signature. Called by tlsFindings in tlsCheckFindings.ts, which
 * keeps the order stable: protocols, certificate, trust, cipher.
 */
import { vuln, type ScanVulnerability } from "./scannerTypes";
import { type TlsHandshakeResult } from "./tlsCheckTypes";
import { DAY_MS, EXPIRY_WARNING_DAYS, REPORTED_SEPARATELY, LEAF_ONLY, WEAK_HASH, hostPort, days, ago, certLines, certificateState, expiryWarningMs } from "./tlsCheckShared";

export function certificateFindings(findings: ScanVulnerability[], r: TlsHandshakeResult, now: Date): void {
  const target = hostPort(r);
  const cert = r.certificate;

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
  } else if (cert && validity.state === "valid" && Date.parse(cert.notAfter!) - now.getTime() < expiryWarningMs(cert)) {
    const warningMs = expiryWarningMs(cert);
    const shortLived = warningMs < EXPIRY_WARNING_DAYS * DAY_MS;
    const lifetimeDays = Math.round((warningMs * 3) / DAY_MS);
    findings.push(vuln({
      name: "TLS Certificate Expires Soon",
      severity: "low",
      category: "Transport Security",
      description: `The certificate the server presents expires in ${days(validity.days)} (the warning threshold is ${shortLived ? `the last third of its ${lifetimeDays}-day lifetime` : EXPIRY_WARNING_DAYS}). When it lapses the site fails for every visitor. Automatic renewal normally replaces a certificate well before this point, so a certificate this close to expiry suggests renewal is not working.`,
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
}
