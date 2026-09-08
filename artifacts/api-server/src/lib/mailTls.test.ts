import { describe, it, expect, afterEach } from "vitest";
import net from "node:net";
import { mailTlsFindings, type MailHostResult, type MailPortResult } from "./mailTls.js";

// ── helpers ────────────────────────────────────────────────────────────────

function port(overrides: Partial<MailPortResult> = {}): MailPortResult {
  return {
    port: 587,
    reachable: true,
    mode: "starttls",
    starttlsAdvertised: true,
    tlsProtocol: "TLSv1.3",
    certIssuer: "Let's Encrypt",
    certValidTo: "Dec 31 23:59:59 2027 GMT",
    daysToExpiry: 300,
    banner: "220 mx.example.com ESMTP",
    error: null,
    ...overrides,
  };
}

function host(ports: MailPortResult[], name = "mx.example.com"): MailHostResult {
  return { host: name, priority: 10, ports };
}

// ── findings ───────────────────────────────────────────────────────────────

describe("mailTlsFindings", () => {
  it("reports a host that accepted SMTP but advertised no STARTTLS", () => {
    // The case worth catching: mail is relayed to this host in cleartext while
    // the website itself scores perfectly on HTTPS.
    const f = mailTlsFindings([
      host([
        port({ port: 25, starttlsAdvertised: false, mode: null }),
        port({ port: 587, starttlsAdvertised: false, mode: null }),
      ]),
    ]);
    expect(f).toHaveLength(1);
    expect(f[0].name).toBe("Mail Server Does Not Offer STARTTLS");
    expect(f[0].severity).toBe("medium");
    expect(f[0].evidence).toContain("mx.example.com:25");
  });

  it("stays silent when STARTTLS is advertised on any cleartext port", () => {
    const f = mailTlsFindings([
      host([
        port({ port: 25, starttlsAdvertised: false, mode: null }),
        port({ port: 587, starttlsAdvertised: true, mode: "starttls" }),
      ]),
    ]);
    expect(f.filter((v) => v.name.includes("STARTTLS"))).toHaveLength(0);
  });

  it("stays silent when a host connected but never answered EHLO", () => {
    // Regression: cloudflare.com. Its MX completes the TCP handshake and then
    // resets before replying to EHLO, so starttlsAdvertised is null — we
    // learned nothing. Gating on `reachable` scored that silence as "no
    // STARTTLS" and reported a domain whose mail transport is fine. It fired
    // only on some runs, which is how a non-deterministic report reaches a
    // customer before anyone can reproduce it.
    const f = mailTlsFindings([
      host([port({ port: 25, reachable: true, starttlsAdvertised: null, mode: null, daysToExpiry: null, error: "read ECONNRESET" })]),
    ]);
    expect(f).toEqual([]);
  });

  it("still reports a host that answered EHLO without STARTTLS, alongside a silent one", () => {
    // The definite-answer rule must not become a blanket mute: one host
    // genuinely offering cleartext is still a finding even when a sibling MX
    // says nothing.
    const f = mailTlsFindings([
      host([port({ port: 25, starttlsAdvertised: null, mode: null, error: "read ECONNRESET" })], "quiet.example.com"),
      host([port({ port: 25, starttlsAdvertised: false, mode: null, daysToExpiry: null })], "cleartext.example.com"),
    ]);
    expect(f.filter((v) => v.name === "Mail Server Does Not Offer STARTTLS")).toHaveLength(1);
    expect(f[0].evidence).toContain("cleartext.example.com:25");
  });

  it("reports nothing at all for a host that never answered", () => {
    // Unreachable is not insecure. Reporting a timeout as a vulnerability is
    // precisely the class of false positive this scanner has been paying down.
    const f = mailTlsFindings([
      host([
        port({ port: 25, reachable: false, mode: null, starttlsAdvertised: null, daysToExpiry: null, error: "connect timeout" }),
        port({ port: 587, reachable: false, mode: null, starttlsAdvertised: null, daysToExpiry: null, error: "connect timeout" }),
        port({ port: 465, reachable: false, mode: null, starttlsAdvertised: null, daysToExpiry: null, error: "connect timeout" }),
      ]),
    ]);
    expect(f).toEqual([]);
  });

  it("flags an expired mail certificate as high", () => {
    const f = mailTlsFindings([host([port({ daysToExpiry: -3, certValidTo: "Jan 01 00:00:00 2026 GMT" })])]);
    const expired = f.find((v) => v.name === "Mail Server TLS Certificate Expired");
    expect(expired?.severity).toBe("high");
    expect(expired?.description).toContain("3 day");
  });

  it("flags an imminent expiry as low, but not a healthy certificate", () => {
    const soon = mailTlsFindings([host([port({ daysToExpiry: 5 })])]);
    expect(soon.find((v) => v.name === "Mail Server TLS Certificate Expiring Soon")?.severity).toBe("low");

    const healthy = mailTlsFindings([host([port({ daysToExpiry: 120 })])]);
    expect(healthy.filter((v) => v.name.includes("Certificate"))).toHaveLength(0);
  });

  it("says nothing when no certificate was ever read", () => {
    // daysToExpiry null means the handshake never completed, not that the
    // certificate is bad.
    const f = mailTlsFindings([host([port({ daysToExpiry: null, certValidTo: null })])]);
    expect(f.filter((v) => v.name.includes("Certificate"))).toHaveLength(0);
  });

  it("returns nothing for a domain with no MX hosts", () => {
    // Covers RFC 7505 null MX: a domain that deliberately accepts no mail must
    // not be reported as having insecure mail.
    expect(mailTlsFindings([])).toEqual([]);
  });
});

// ── live negotiation against a local SMTP stub ─────────────────────────────

describe("probeStartTls (against a local stub)", () => {
  const servers: net.Server[] = [];
  afterEach(() => { for (const s of servers) s.close(); servers.length = 0; });

  /**
   * Minimal SMTP responder: greeting, an EHLO reply we control, and a refusal
   * to actually upgrade.
   *
   * The refusal matters. Without it a stub that advertises STARTTLS leaves the
   * probe waiting for a 220 that never arrives, so the test only ends on the
   * read timeout. Refusing exercises the advertised-but-unusable path and keeps
   * the test fast.
   */
  function stub(ehloReply: string): Promise<number> {
    return new Promise((resolve) => {
      const server = net.createServer((sock) => {
        sock.write("220 stub.invalid ESMTP ready\r\n");
        sock.on("data", (d) => {
          const line = d.toString();
          if (/^EHLO/i.test(line)) sock.write(ehloReply);
          else if (/^STARTTLS/i.test(line)) sock.write("454 TLS not available\r\n");
        });
      });
      servers.push(server);
      server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port));
    });
  }

  it("reads the banner and detects an advertised STARTTLS capability", async () => {
    const { probeStartTlsForTest } = await import("./mailTls.js");
    const p = await stub("250-stub.invalid\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n");
    const r = await probeStartTlsForTest("127.0.0.1", p);
    expect(r.reachable).toBe(true);
    expect(r.banner).toContain("220 stub.invalid");
    expect(r.starttlsAdvertised).toBe(true);
    // The stub refuses the upgrade, so the capability is recorded while the
    // handshake is reported as failed rather than quietly assumed to work.
    expect(r.mode).toBeNull();
    expect(r.error).toContain("STARTTLS refused");
  });

  it("detects a server that advertises no STARTTLS", async () => {
    const { probeStartTlsForTest } = await import("./mailTls.js");
    const p = await stub("250-stub.invalid\r\n250 SIZE 10240000\r\n");
    const r = await probeStartTlsForTest("127.0.0.1", p);
    expect(r.reachable).toBe(true);
    expect(r.starttlsAdvertised).toBe(false);
    // No handshake was attempted, so no certificate data should be invented.
    expect(r.mode).toBeNull();
    expect(r.daysToExpiry).toBeNull();
  });

  it("reports an unreachable port without inventing a finding", async () => {
    const { probeStartTlsForTest } = await import("./mailTls.js");
    // Port 1 on loopback: nothing listens, connection refused immediately.
    const r = await probeStartTlsForTest("127.0.0.1", 1);
    expect(r.reachable).toBe(false);
    expect(r.starttlsAdvertised).toBeNull();
    expect(mailTlsFindings([host([r])])).toEqual([]);
  });
});
