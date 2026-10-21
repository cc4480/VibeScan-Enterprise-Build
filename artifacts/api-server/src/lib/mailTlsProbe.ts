/** The STARTTLS handshake against each MX host. */
import net from "node:net";
import tls from "node:tls";
import { checkHostname } from "./ssrfGuard";
import { strictLookup } from "./pinnedDispatcher";

/**
 * Most bytes of server reply the probe will buffer while looking for a line break. A real greeting or
 * EHLO reply is a few hundred bytes; a server that never sends a newline must not grow the buffer forever.
 */
export const MAX_REPLY_BYTES = 8 * 1024;

/** Hard ceiling per socket. A slow MX must never stall the whole scan. */
export const CONNECT_TIMEOUT_MS = 6_000;

/** How long to wait for the greeting and for each command response. */
export const READ_TIMEOUT_MS = 5_000;

/**
 * Absolute ceiling on the whole probe, independent of CONNECT_TIMEOUT_MS /
 * READ_TIMEOUT_MS.
 *
 * Those two are socket.setTimeout() idle timers: they reset on ANY activity,
 * not just a full reply. A mail server that tarpits -- a standard anti-spam
 * technique of drip-feeding bytes to waste an automated sender's time -- keeps
 * resetting the idle clock forever without ever finishing the SMTP exchange,
 * so the socket never times out at all. Reproduced live against a real
 * production MX host (IONOS): the idle-timeout version hung 30+ seconds with
 * no result. This is a separate, unconditional deadline that fires and calls
 * finish() no matter what the socket is doing.
 */
export const OVERALL_TIMEOUT_MS = 12_000;

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
export const MX_SMTP_PORT = 25;

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
  /**
   * Set when the probe was deliberately not run (the MX names a private, loopback or otherwise local
   * address). Not an error and not evidence: the host was never connected to.
   */
  skipped?: string;
}

export interface MailHostResult {
  host: string;
  priority: number;
  ports: MailPortResult[];
}

export function emptyPort(port: number): MailPortResult {
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

export function daysUntil(validTo: string): number | null {
  const t = Date.parse(validTo);
  if (Number.isNaN(t)) return null;
  return Math.floor((t - Date.now()) / 86_400_000);
}

/** Issuer CN if present, else the raw O= value — enough to name the CA. */
export function issuerName(cert: tls.PeerCertificate): string | null {
  const i = cert.issuer as unknown as Record<string, string> | undefined;
  if (!i) return null;
  return i.CN || i.O || null;
}

export function readCert(socket: tls.TLSSocket, out: MailPortResult): void {
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
export async function probeStartTls(host: string, port: number): Promise<MailPortResult> {
  // The MX name comes from DNS, and a domain owner controls DNS. Refuse anything that is not a public address,
  // and connect through the vetted lookup so the address checked is the address dialled (no rebinding window).
  const verdict = await checkHostname(host);
  if (!verdict.ok) {
    return { ...emptyPort(port), skipped: `not probed: ${verdict.reason ?? "private address"}` };
  }
  return negotiate(host, port, strictLookup);
}

/**
 * Test seam: the same negotiation with no address check, so the tests can drive it against a loopback stub.
 * Production code calls probeStartTls, which is the only path that reaches a mail exchanger.
 */
export function probeStartTlsForTest(host: string, port: number): Promise<MailPortResult> {
  return negotiate(host, port, undefined);
}

function negotiate(host: string, port: number, lookup: unknown): Promise<MailPortResult> {
  return new Promise((resolve) => {
    const out = emptyPort(port);
    let settled = false;
    let buf = "";
    let stage: "greeting" | "ehlo" | "starttls" = "greeting";

    const socket = new net.Socket();
    // Absolute deadline -- see OVERALL_TIMEOUT_MS. Cleared in finish() only
    // for hygiene (finish() already destroys the socket either way).
    const overallDeadline = setTimeout(() => {
      out.error = out.error ?? "overall probe timeout (server drip-feeding data)";
      finish();
    }, OVERALL_TIMEOUT_MS);
    const finish = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(overallDeadline);
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
      if (buf.length > MAX_REPLY_BYTES) {
        out.error = "server reply exceeds 8 KB without a line break";
        finish();
        return;
      }
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

    socket.connect(lookup ? { port, host, lookup: lookup as never } : { port, host });
  });
}

/** Probe the inbound SMTP port on one MX host. */
export async function probeHost(host: string, priority: number): Promise<MailHostResult> {
  return { host, priority, ports: [await probeStartTls(host, MX_SMTP_PORT)] };
}
