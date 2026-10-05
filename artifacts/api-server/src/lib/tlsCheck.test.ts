/**
 * The TLS configuration check against real sockets: local TLS servers on 127.0.0.1 with certificates
 * generated here with openssl (the suite skips if openssl is missing). Nothing leaves the machine.
 *
 * The vitest config sets ALLOW_PRIVATE_SCAN_TARGETS=true so probes can reach loopback; the tests of
 * the refusal switch it off.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import dns from "node:dns";
import net, { type AddressInfo } from "node:net";
import tls from "node:tls";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";
import { classifyHandshakeError, describeCertificate, inspectTls, signatureAlgorithmOf } from "./tlsCheck";
import { tlsFindings } from "./tlsCheckFindings";
import { _clearResolveCache } from "./ssrfGuard";
import type { TlsHandshakeResult, TlsInspection } from "./tlsCheckTypes";

function opensslAvailable(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const HAVE_OPENSSL = opensslAvailable();

describe("classifyHandshakeError", () => {
  it("reads the scanner's own refusal to offer a protocol as local, not as the server's answer", () => {
    expect(classifyHandshakeError({ code: "ERR_SSL_NO_PROTOCOLS_AVAILABLE", reason: "no protocols available" })).toBe("local");
    expect(classifyHandshakeError({ message: "error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available" })).toBe("local");
    expect(classifyHandshakeError({ code: "ERR_TLS_INVALID_PROTOCOL_VERSION" })).toBe("local");
  });

  it("reads an alert or a reply naming another version as the server refusing", () => {
    expect(classifyHandshakeError({ code: "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION", reason: "tlsv1 alert protocol version" })).toBe("refused");
    expect(classifyHandshakeError({ code: "ERR_SSL_UNSUPPORTED_PROTOCOL", reason: "unsupported protocol" })).toBe("refused");
    expect(classifyHandshakeError({ code: "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE" })).toBe("refused");
  });

  it("reads a reset or hang-up as ambiguous: no alert came back, so it is not evidence either way", () => {
    expect(classifyHandshakeError({ code: "ECONNRESET", message: "read ECONNRESET" })).toBe("closed");
    expect(classifyHandshakeError({ message: "Client network socket disconnected before secure TLS connection was established" })).toBe("closed");
    expect(classifyHandshakeError({ code: "ERR_SSL_UNEXPECTED_EOF_WHILE_READING" })).toBe("closed");
  });

  it("reads a weak server certificate as a security-level refusal the probe can retry past", () => {
    expect(classifyHandshakeError({ code: "ERR_SSL_EE_KEY_TOO_SMALL", reason: "ee key too small" })).toBe("security-level");
    expect(classifyHandshakeError({ reason: "ca md too weak" })).toBe("security-level");
  });

  it("separates a blocked address and plain network failures", () => {
    expect(classifyHandshakeError({ code: "ESSRFBLOCKED" })).toBe("blocked");
    for (const code of ["ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND", "EHOSTUNREACH"]) expect(classifyHandshakeError({ code }), code).toBe("network");
  });
});

describe("signatureAlgorithmOf", () => {
  it.skipIf(!HAVE_OPENSSL)("reads the algorithm out of real certificates, and returns null for bytes that are not one", () => {
    const dir = mkdtempSync(join(tmpdir(), "tlsalg-"));
    try {
      const make = (name: string, args: string[]) => {
        execFileSync("openssl", ["req", "-x509", "-nodes", "-days", "2", "-subj", "/CN=alg.test", "-keyout", join(dir, `${name}.key`), "-out", join(dir, `${name}.pem`), ...args], { stdio: "ignore" });
        return new X509Certificate(readFileSync(join(dir, `${name}.pem`))).raw;
      };
      expect(signatureAlgorithmOf(make("rsa256", ["-newkey", "rsa:2048", "-sha256"]))).toBe("sha256WithRSAEncryption");
      expect(signatureAlgorithmOf(make("rsa1", ["-newkey", "rsa:2048", "-sha1"]))).toBe("sha1WithRSAEncryption");
      expect(signatureAlgorithmOf(make("ec384", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp384r1", "-sha384"]))).toBe("ecdsa-with-SHA384");
      expect(signatureAlgorithmOf(make("ed", ["-newkey", "ed25519"]))).toBe("Ed25519");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    expect(signatureAlgorithmOf(Buffer.from("not a certificate"))).toBeNull();
    expect(signatureAlgorithmOf(Buffer.alloc(0))).toBeNull();
    expect(signatureAlgorithmOf(Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]))).toBeNull();
  });
});

describe("describeCertificate", () => {
  it("returns null when the server presented nothing", () => {
    expect(describeCertificate("example.com", {} as tls.PeerCertificate)).toBeNull();
  });
});

// ── Live servers ─────────────────────────────────────────────────────────────

interface Pem { key: string; cert: string }

describe.skipIf(!HAVE_OPENSSL)("inspectTls against local servers", () => {
  const dir = mkdtempSync(join(tmpdir(), "tlscheck-"));
  const servers: net.Server[] = [];
  let ok: Pem;
  let wrongName: Pem;
  let expired: Pem;
  let weak: Pem;

  /** A self-signed certificate. `x509Days` makes it through `openssl x509`, which accepts a negative lifetime. */
  function makeCert(name: string, o: { sans: string; bits?: number; sha?: string; days?: number; x509Days?: number }): Pem {
    const keyFile = join(dir, `${name}.key`);
    const certFile = join(dir, `${name}.pem`);
    if (o.x509Days !== undefined) {
      const ext = join(dir, `${name}.ext`);
      writeFileSync(ext, `subjectAltName=${o.sans}\n`);
      execFileSync("openssl", ["genrsa", "-out", keyFile, String(o.bits ?? 2048)], { stdio: "ignore" });
      execFileSync("openssl", ["req", "-new", "-key", keyFile, "-subj", "/CN=localhost", "-out", join(dir, `${name}.csr`)], { stdio: "ignore" });
      execFileSync("openssl", ["x509", "-req", "-in", join(dir, `${name}.csr`), "-signkey", keyFile, "-days", String(o.x509Days), "-extfile", ext, "-out", certFile], { stdio: "ignore" });
    } else {
      execFileSync("openssl", [
        "req", "-x509", "-newkey", `rsa:${o.bits ?? 2048}`, "-nodes", "-keyout", keyFile, "-out", certFile,
        "-days", String(o.days ?? 30), "-subj", "/CN=localhost", "-addext", `subjectAltName=${o.sans}`, `-${o.sha ?? "sha256"}`,
      ], { stdio: "ignore" });
    }
    return { key: readFileSync(keyFile, "utf8"), cert: readFileSync(certFile, "utf8") };
  }

  beforeAll(() => {
    ok = makeCert("ok", { sans: "DNS:localhost,IP:127.0.0.1" });
    wrongName = makeCert("wrong", { sans: "DNS:somewhere-else.test" });
    expired = makeCert("expired", { sans: "DNS:localhost,IP:127.0.0.1", x509Days: -1 });
    weak = makeCert("weak", { sans: "DNS:localhost,IP:127.0.0.1", bits: 1024, sha: "sha1" });
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    _clearResolveCache();
    await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
  });

  /** A TLS server on 127.0.0.1 that counts the TCP connections it receives. */
  async function serve(pem: Pem, opts: tls.TlsOptions = {}): Promise<{ port: number; connections: () => number }> {
    let connections = 0;
    const server = tls.createServer({ key: pem.key, cert: pem.cert, ...opts }, (s) => s.end());
    server.on("tlsClientError", () => {});
    server.on("connection", () => { connections++; });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    servers.push(server);
    return { port: (server.address() as AddressInfo).port, connections: () => connections };
  }

  const inspected = (i: TlsInspection): TlsHandshakeResult => {
    if (i.status !== "inspected") throw new Error(`expected an inspection, got ${i.status}: ${"reason" in i ? i.reason : ""}`);
    return i.result;
  };
  const names = (r: TlsHandshakeResult) => tlsFindings(r).map((f) => f.name);

  it("reads a TLS 1.2 server with a self-signed certificate: protocols, cipher, certificate, trust", async () => {
    const { port } = await serve(ok, { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" });
    const r = inspected(await inspectTls(`https://127.0.0.1:${port}/some/path`));

    expect(r.host).toBe("127.0.0.1");
    expect(r.port).toBe(port);
    expect(r.protocols["TLSv1.2"].status).toBe("accepted");
    expect(r.protocols["TLSv1.3"].status).toBe("rejected");
    // Legacy versions are best effort: refused by the server, or untested if this machine's OpenSSL will not offer them.
    for (const v of ["TLSv1", "TLSv1.1"] as const) expect(["rejected", "untested"]).toContain(r.protocols[v].status);
    expect(r.negotiated?.protocol).toBe("TLSv1.2");
    expect(r.negotiated?.cipher).toMatch(/ECDHE/);
    expect(r.trusted).toBe(false);
    expect(r.trustError).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");

    const c = r.certificate!;
    expect(c.subject).toBe("localhost");
    expect(c.selfSigned).toBe(true);
    expect(c.hostnameMatches).toBe(true);
    expect(c.subjectAltNames).toEqual(expect.arrayContaining(["localhost", "127.0.0.1"]));
    expect(c.keyType).toBe("RSA");
    expect(c.keyBits).toBe(2048);
    expect(c.signatureAlgorithm).toBe("sha256WithRSAEncryption");
    expect(Date.parse(c.notAfter!)).toBeGreaterThan(Date.now());

    expect(names(r)).toEqual(["Self-Signed TLS Certificate"]);
  });

  it("honours the port in the URL, and finds TLS 1.3 only on a TLS 1.3 server", async () => {
    const { port } = await serve(ok, { minVersion: "TLSv1.3" });
    const r = inspected(await inspectTls(`https://127.0.0.1:${port}`));
    expect(r.port).toBe(port);
    expect(r.negotiated?.protocol).toBe("TLSv1.3");
    expect(r.protocols["TLSv1.3"].status).toBe("accepted");
    expect(r.protocols["TLSv1.2"].status).toBe("rejected");
  });

  it("finds a server that still accepts TLS 1.0 and 1.1, and reports it only if the handshake really completed", async () => {
    const { port } = await serve(ok, { minVersion: "TLSv1", maxVersion: "TLSv1.1", ciphers: "DEFAULT:@SECLEVEL=0" });
    const r = inspected(await inspectTls(`https://127.0.0.1:${port}`));
    for (const v of ["TLSv1", "TLSv1.1"] as const) {
      // accepted here; "untested" only if this machine's OpenSSL cannot offer the version. Never "rejected" by a server that accepts it.
      expect(["accepted", "untested"], v).toContain(r.protocols[v].status);
    }
    expect(r.protocols["TLSv1.2"].status).toBe("rejected");
    expect(r.protocols["TLSv1.3"].status).toBe("rejected");
    const accepted = r.protocols["TLSv1"].status === "accepted" || r.protocols["TLSv1.1"].status === "accepted";
    expect(names(r).includes("Deprecated TLS Protocol Versions Accepted")).toBe(accepted);
    if (r.protocols["TLSv1"].status === "untested") expect(r.protocols["TLSv1"].detail).toMatch(/could not|would not offer|closed/i);
  });

  it("flags a certificate that does not cover the host it was reached by", async () => {
    const { port } = await serve(wrongName);
    const r = inspected(await inspectTls(`https://127.0.0.1:${port}`));
    expect(r.certificate!.hostnameMatches).toBe(false);
    expect(r.certificate!.hostnameError).toBeTruthy();
    expect(names(r)).toContain("TLS Certificate Does Not Match the Hostname");
  });

  it("flags an expired certificate", async () => {
    const { port } = await serve(expired);
    const r = inspected(await inspectTls(`https://127.0.0.1:${port}`));
    expect(Date.parse(r.certificate!.notAfter!)).toBeLessThan(Date.now());
    expect(names(r)).toContain("TLS Certificate Expired");
  });

  it("still reads a certificate with a 1024-bit key and a SHA-1 signature that the scanner's own OpenSSL would refuse by default", async () => {
    const { port } = await serve(weak, { ciphers: "DEFAULT:@SECLEVEL=0" });
    const r = inspected(await inspectTls(`https://127.0.0.1:${port}`));
    expect(r.certificate!.keyBits).toBe(1024);
    expect(r.certificate!.signatureAlgorithm).toBe("sha1WithRSAEncryption");
    expect(names(r)).toEqual(expect.arrayContaining(["TLS Certificate Key Too Short", "TLS Certificate Signed With a Weak Hash"]));
  });

  it("resolves a hostname through the vetted lookup and connects", async () => {
    const { port } = await serve(ok);
    const r = inspected(await inspectTls(`https://localhost:${port}`));
    expect(r.certificate!.hostnameMatches).toBe(true);
    expect(r.protocols["TLSv1.2"].status).toBe("accepted");
  });

  describe("safety", () => {
    it("refuses a loopback address when private targets are not allowed, and opens no connection", async () => {
      vi.stubEnv("ALLOW_PRIVATE_SCAN_TARGETS", "");
      const { port, connections } = await serve(ok);
      const i = await inspectTls(`https://127.0.0.1:${port}`);
      expect(i.status).toBe("skipped");
      expect(i.status === "skipped" && i.reason).toMatch(/^refused:.*private or local/);
      expect(connections()).toBe(0);
    });

    it("refuses other private and local targets the same way", async () => {
      vi.stubEnv("ALLOW_PRIVATE_SCAN_TARGETS", "");
      for (const url of ["https://localhost:8443", "https://10.0.0.5", "https://192.168.1.10:8443", "https://169.254.169.254", "https://[::1]:8443", "https://intranet"]) {
        const i = await inspectTls(url, { timeoutMs: 500 });
        expect(i.status, url).toBe("skipped");
        expect(i.status === "skipped" && i.reason, url).toMatch(/^refused:/);
      }
    });

    it("refuses a name that resolves to loopback (DNS rebinding) when the connection is made, and opens no connection", async () => {
      vi.stubEnv("ALLOW_PRIVATE_SCAN_TARGETS", "");
      const { port, connections } = await serve(ok);
      vi.spyOn(dns, "lookup").mockImplementation(((_h: string, _o: unknown, cb: (e: null, a: { address: string; family: number }[]) => void) =>
        cb(null, [{ address: "127.0.0.1", family: 4 }])) as never);
      const i = await inspectTls(`https://rebind.attacker.test:${port}`);
      expect(i.status).toBe("skipped");
      expect(i.status === "skipped" && i.reason).toMatch(/^refused:/);
      expect(connections()).toBe(0);
    });

    it("refuses a name when any one of its addresses is private", async () => {
      vi.stubEnv("ALLOW_PRIVATE_SCAN_TARGETS", "");
      vi.spyOn(dns, "lookup").mockImplementation(((_h: string, _o: unknown, cb: (e: null, a: { address: string; family: number }[]) => void) =>
        cb(null, [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.5", family: 4 }])) as never);
      const i = await inspectTls("https://mixed.attacker.test");
      expect(i.status).toBe("skipped");
    });
  });

  describe("when there is nothing to inspect, or it cannot be reached", () => {
    it("skips a target that is not HTTPS", async () => {
      const i = await inspectTls("http://127.0.0.1:8080");
      expect(i).toEqual({ status: "skipped", reason: expect.stringMatching(/not served over HTTPS/) });
    });

    it("skips what is not a URL", async () => {
      expect((await inspectTls("not a url")).status).toBe("skipped");
    });

    it("fails, with the reason, when nothing is listening", async () => {
      const probe = net.createServer();
      await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
      const { port } = probe.address() as AddressInfo;
      await new Promise<void>((r) => probe.close(() => r()));
      const i = await inspectTls(`https://127.0.0.1:${port}`);
      expect(i.status).toBe("failed");
      expect(i.status === "failed" && i.reason).toMatch(/could not connect to 127\.0\.0\.1/);
    });

    it("gives up on a server that accepts the connection and never answers, within the timeout", async () => {
      // Reads and discards, so the server sees the client hang up and can close.
      const silent = net.createServer((s) => { s.on("error", () => {}); s.resume(); });
      await new Promise<void>((r) => silent.listen(0, "127.0.0.1", r));
      servers.push(silent);
      const started = Date.now();
      const i = await inspectTls(`https://127.0.0.1:${(silent.address() as AddressInfo).port}`, { timeoutMs: 400 });
      expect(i.status).toBe("failed");
      expect(i.status === "failed" && i.reason).toMatch(/timed out/);
      expect(Date.now() - started).toBeLessThan(3_000);
    });

    it("fails when the port speaks something other than TLS", async () => {
      const plain = net.createServer((s) => {
        s.on("error", () => {});
        s.resume();
        s.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      });
      await new Promise<void>((r) => plain.listen(0, "127.0.0.1", r));
      servers.push(plain);
      const i = await inspectTls(`https://127.0.0.1:${(plain.address() as AddressInfo).port}`, { timeoutMs: 2_000 });
      expect(i.status).toBe("failed");
      expect(i.status === "failed" && i.reason).toMatch(/no TLS handshake completed/);
    });
  });
});
