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
import net from "node:net";
import tls from "node:tls";
import { randomUUID } from "node:crypto";
import { promises as dns } from "node:dns";
// MxRecord lives on the callback-style dns namespace, not dns/promises.
import type { MxRecord } from "node:dns";
import type { ScanVulnerability } from "./scanner.js";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/** Hard ceiling per socket. A slow MX must never stall the whole scan. */
const CONNECT_TIMEOUT_MS = 6_000;
/** How long to wait for the greeting and for each command response. */
const READ_TIMEOUT_MS = 5_000;
/** Only the highest-priority hosts are probed; a domain may list many. */
const MAX_MX_HOSTS = 3;

/**
 * The only port worth probing on an MX host.
 *
 * An MX is an INBOUND relay: every message the world sends to this domain
 * arrives on 25, so 25 alone answers "is mail to this domain encrypted in
 * transit". Ports 587 and 465 are SUBMISSION ports, for the domain own
 * authenticated users, and normally live on a different hostname
 * (smtp.example.com). Probing them here measured nothing and cost ~5s of every
 * scan: Google firewalls both (6s connect timeout), Cloudflare resets 587 after
 * the TCP handshake. That reset also produced a real false positive — see the
 * definite-answer rule in mailTlsFindings.
 */
const MX_SMTP_PORT = 25;

export interface MailPortResult {
  port: number;
  reachable: boolean;
  /** "starttls" once the upgrade completed, else null. */
  mode: "starttls" | null;
  /**
   * true/false once the server answered EHLO; null when it never did.
   *
   * The null is load-bearing: it means "we learned nothing", which is not the
   * same as "no STARTTLS" and must never be reported as such.
   */
  starttlsAdvertised: boolean | null;
  tlsProtocol: string | null;
  certIssuer: string | null;
  certValidTo: string | null;
  daysToExpiry: number | null;
  banner: string | null;
  error: string | null;
}

export interface MailHostResult {
  host: string;
  priority: number;
  ports: MailPortResult[];
}

function emptyPort(port: number): MailPortResult {
  return {
    port,
    reachable: false,
    mode: null,
    starttlsAdvertised: null,
    tlsProtocol: null,
    certIssuer: null,
    certValidTo: null,
    daysToExpiry: null,
    banner: null,
    error: null,
  };
}

function daysUntil(validTo: string): number | null {
  const t = Date.parse(validTo);
  if (Number.isNaN(t)) return null;
  return Math.floor((t - Date.now()) / 86_400_000);
}

/** Issuer CN if present, else the raw O= value — enough to name the CA. */
function issuerName(cert: tls.PeerCertificate): string | null {
  const i = cert.issuer as unknown as Record<string, string> | undefined;
  if (!i) return null;
  return i.CN || i.O || null;
}

function readCert(socket: tls.TLSSocket, out: MailPortResult): void {
  const cert = socket.getPeerCertificate();
  out.tlsProtocol = socket.getProtocol();
  if (cert && Object.keys(cert).length > 0) {
    out.certIssuer = issuerName(cert);
    out.certValidTo = cert.valid_to ?? null;
    out.daysToExpiry = cert.valid_to ? daysUntil(cert.valid_to) : null;
  }
}

/**
 * STARTTLS: greeting, EHLO, read capabilities, then upgrade if offered.
 *
 * The capability list is the finding either way — a server that never
 * advertises STARTTLS accepts mail in cleartext, which is the thing worth
 * reporting whether or not the upgrade itself succeeds.
 */
function probeStartTls(host: string, port: number): Promise<MailPortResult> {
  return new Promise((resolve) => {
    const out = emptyPort(port);
    let settled = false;
    let buf = "";
    let stage: "greeting" | "ehlo" | "starttls" = "greeting";

    const socket = new net.Socket();
    const finish = (): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(out);
    };

    // Upgrading reuses the live socket, so the plaintext handlers must come off
    // first or they keep consuming the now-encrypted stream.
    const upgrade = (): void => {
      socket.removeAllListeners("data");
      socket.removeAllListeners("timeout");
      const secure = tls.connect(
        { socket, servername: host, rejectUnauthorized: false },
        () => {
          out.mode = "starttls";
          readCert(secure, out);
          if (!settled) { settled = true; secure.destroy(); resolve(out); }
        },
      );
      secure.setTimeout(READ_TIMEOUT_MS);
      secure.on("timeout", () => { out.error = "tls handshake timeout"; finish(); });
      secure.on("error", (err: Error) => {
        // Advertised but unusable is still worth knowing, so the capability
        // stays recorded and only the handshake is reported as failed.
        out.error = `starttls handshake failed: ${err.message.slice(0, 90)}`;
        finish();
      });
    };

    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.on("connect", () => {
      out.reachable = true;
      socket.setTimeout(READ_TIMEOUT_MS);
    });

    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      if (stage === "greeting") {
        if (!/\r?\n/.test(buf)) return;
        out.banner = buf.split(/\r?\n/)[0]?.slice(0, 200) ?? null;
        buf = "";
        stage = "ehlo";
        socket.write(`EHLO scanner.invalid\r\n`);
        return;
      }
      if (stage === "ehlo") {
        // EHLO replies are multi-line: "250-CAP" for each, "250 CAP" last.
        if (!/^250 [^\r\n]*\r?\n?$/m.test(buf) && !/\r?\n250 /.test(buf)) return;
        out.starttlsAdvertised = /STARTTLS/i.test(buf);
        if (!out.starttlsAdvertised) { finish(); return; }
        buf = "";
        stage = "starttls";
        socket.write("STARTTLS\r\n");
        return;
      }
      // stage === "starttls": 220 means go ahead.
      if (/^220/.test(buf.trim())) upgrade();
      else { out.error = `STARTTLS refused: ${buf.trim().slice(0, 80)}`; finish(); }
    });

    socket.on("timeout", () => {
      // A reachable host that went quiet still yielded its capabilities.
      out.error = out.reachable ? "read timeout" : "connect timeout";
      finish();
    });
    socket.on("error", (err: Error) => { out.error = err.message.slice(0, 120); finish(); });

    socket.connect(port, host);
  });
}

// Exported for tests. The SMTP negotiation — greeting, multi-line EHLO,
// capability detection — is where the bugs hide, and it is only reachable
// through a live socket, so the tests drive it against a local stub server.
export { probeStartTls as probeStartTlsForTest };

/** Probe the inbound SMTP port on one MX host. */
async function probeHost(host: string, priority: number): Promise<MailHostResult> {
  return { host, priority, ports: [await probeStartTls(host, MX_SMTP_PORT)] };
}

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
