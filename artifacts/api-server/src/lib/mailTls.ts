/**
 * Mail-server transport security.
 *
 * Resolves the domain's MX hosts and asks each one what it actually does when
 * SMTP knocks: does it offer STARTTLS on 25/587, does it speak implicit TLS on
 * 465, and is the certificate it presents valid and unexpired.
 *
 * This matters because it is invisible from the web tier. A site can score
 * perfectly on HTTPS while its mail exchanger accepts mail in cleartext, and
 * password resets, invoices and account notifications all travel through that
 * exchanger. DNS-level checks (SPF/DMARC) say who MAY send; they say nothing
 * about whether the transport is encrypted.
 *
 * Non-intrusive by construction. It connects, reads the banner, sends EHLO and
 * (on 25/587) STARTTLS, then hangs up. No authentication, no MAIL FROM, no
 * message is ever submitted — the same posture as the existing TCP port scanner
 * in recon.ts, which already connects and reads banners.
 */

import { randomUUID } from "node:crypto";
import { promises as dns, MxRecord } from "node:dns";
import type { ScanVulnerability } from "./scanner.js";
import { type MailHostResult, probeHost, probeStartTlsForTest } from "./mailTlsProbe";
export type { MailPortResult, MailHostResult } from "./mailTlsProbe";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}
/** Only the highest-priority hosts are probed; a domain may list many. */
const MAX_MX_HOSTS = 3;

// Exported for tests. The SMTP negotiation — greeting, multi-line EHLO,
// capability detection — is where the bugs hide, and it is only reachable
// through a live socket, so the tests drive it against a local stub server.
export { probeStartTlsForTest };

/**
 * Resolve MX and probe the highest-priority hosts.
 *
 * Returns [] when the domain has no MX at all — that is a mail-routing fact,
 * not a transport-security one, and a domain that deliberately accepts no mail
 * (RFC 7505 null MX) must not be reported as having insecure mail.
 */
export async function inspectMailTls(hostname: string): Promise<MailHostResult[]> {
  let records: MxRecord[];
  try {
    records = await dns.resolveMx(hostname);
  } catch {
    return [];
  }
  const usable = records
    .filter((r) => r.exchange && r.exchange !== ".") // "." is RFC 7505 null MX
    .sort((a, b) => a.priority - b.priority)
    .slice(0, MAX_MX_HOSTS);

  return Promise.all(usable.map((r) => probeHost(r.exchange, r.priority)));
}

/**
 * Turn probe results into findings.
 *
 * Deliberately conservative: only reports what was positively observed. A host
 * that never answered produces nothing — unreachable is not the same as
 * insecure, and reporting a timeout as a vulnerability is exactly the kind of
 * false positive this scanner has been paying down.
 */
export function mailTlsFindings(hosts: MailHostResult[]): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];

  for (const h of hosts) {
    const reachable = h.ports.filter((p) => p.reachable);
    if (reachable.length === 0) continue;

    /**
     * Only ports that gave a definite answer are evidence.
     *
     * Reachability is NOT an answer. A host can complete the TCP handshake and
     * then reset before replying to EHLO, which leaves starttlsAdvertised null
     * — we learned nothing. Gating on reachable treated that silence as "no
     * STARTTLS" and reported cloudflare.com, whose MX advertises STARTTLS on 25
     * perfectly well, as relaying cleartext. It fired on some runs and not
     * others, depending on when the reset landed.
     */
    const answered = reachable.filter((p) => p.starttlsAdvertised !== null);
    const anyStartTls = answered.some((p) => p.starttlsAdvertised === true);

    if (answered.length > 0 && !anyStartTls) {
      findings.push(vuln({
        name: "Mail Server Does Not Offer STARTTLS",
        severity: "medium",
        category: "Mail Transport Security",
        description: `The mail exchanger ${h.host} accepted an SMTP connection but advertised no STARTTLS capability, so mail is relayed to this host in cleartext. Anyone able to observe the path — a transit provider, a compromised network device — can read message contents and credentials in password-reset and notification mail.`,
        evidence: answered
          .map((p) => `EHLO to ${h.host}:${p.port} → capabilities did not include STARTTLS${p.banner ? ` (banner: ${p.banner})` : ""}`)
          .join("\n"),
        solution: "Enable STARTTLS on ports 25 and 587 with a certificate valid for the MX hostname. Postfix: smtpd_tls_security_level = may (or encrypt for submission). Exim: tls_advertise_hosts = *. Then verify with: openssl s_client -starttls smtp -connect host:587",
        cweId: "CWE-319",
        cvssScore: 5.9,
        wstgId: "WSTG-CRYP-01",
        confidence: 85,
      }));
    }

    for (const p of reachable) {
      // A null expiry means no handshake completed, not a bad certificate.
      if (p.daysToExpiry === null) continue;

      if (p.daysToExpiry < 0) {
        findings.push(vuln({
          name: "Mail Server TLS Certificate Expired",
          severity: "high",
          category: "Mail Transport Security",
          description: `The certificate presented by ${h.host} on port ${p.port} expired ${Math.abs(p.daysToExpiry)} day(s) ago. Sending servers that verify certificates will refuse to deliver, and those that fall back to cleartext will do so silently.`,
          evidence: `${h.host}:${p.port} (${p.mode})\nIssuer: ${p.certIssuer ?? "unknown"}\nValid to: ${p.certValidTo}`,
          solution: "Renew the mail server certificate and reload the MTA. Automate renewal (certbot with the appropriate deploy hook) so the mail path is not dependent on a manual step.",
          cweId: "CWE-324",
          cvssScore: 7.4,
          wstgId: "WSTG-CRYP-01",
          confidence: 95,
        }));
      } else if (p.daysToExpiry <= 21) {
        findings.push(vuln({
          name: "Mail Server TLS Certificate Expiring Soon",
          severity: "low",
          category: "Mail Transport Security",
          description: `The certificate presented by ${h.host} on port ${p.port} expires in ${p.daysToExpiry} day(s). Mail delivery is one of the last places an expiry is noticed, because senders commonly downgrade to cleartext rather than bounce.`,
          evidence: `${h.host}:${p.port} (${p.mode})\nIssuer: ${p.certIssuer ?? "unknown"}\nValid to: ${p.certValidTo}`,
          solution: "Renew before expiry and confirm automated renewal actually reloads the MTA — a renewed file that the running process has not re-read changes nothing.",
          cweId: "CWE-324",
          cvssScore: 3.1,
          wstgId: "WSTG-CRYP-01",
          confidence: 95,
        }));
      }
    }
  }

  return findings;
}