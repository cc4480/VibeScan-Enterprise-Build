/**
 * The TLS configuration check against real sockets: local TLS servers on 127.0.0.1 with certificates
 * generated here with openssl (the suite skips if openssl is missing). Nothing leaves the machine.
 *
 * The vitest config sets ALLOW_PRIVATE_SCAN_TARGETS=true so probes can reach loopback; the tests of
 * the refusal switch it off.
 */
import { describe, expect, it } from "vitest";
import tls from "node:tls";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";
import { classifyHandshakeError, describeCertificate, signatureAlgorithmOf } from "./tlsCheck";
import { _clearResolveCache } from "./ssrfGuard";

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
