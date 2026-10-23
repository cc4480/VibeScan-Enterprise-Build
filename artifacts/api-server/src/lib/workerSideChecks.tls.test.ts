/**
 * How the worker folds the TLS configuration check and the (opt-in) SSL Labs assessment into a scan:
 * the findings, the ledger lines, and what a report says when SSL Labs is off.
 */
import { afterEach, describe, expect, it } from "vitest";
import { capturedLog } from "./captureLog.testkit";
import {
  TLS_CHECK_TEST,
  mergeTlsCheck,
  recordSideTests,
  sslLabsEnabled,
  tlsCheckRecord,
  type TlsCheckRun,
} from "./workerSideChecks";
import { catalogFor } from "./checkCatalog";
import { resolveTest } from "./checkOutcomes";
import type { ScanResult } from "./scanner";
import type { TlsHandshakeResult, TlsInspection } from "./tlsCheckTypes";
import type { TestRecord } from "./testLedger";

const NOW = new Date("2026-10-05T12:00:00Z");
const day = (d: number) => new Date(NOW.getTime() + d * 86_400_000).toISOString();

const result = (over: Partial<TlsHandshakeResult> = {}): TlsHandshakeResult => ({
  host: "example.com",
  port: 443,
  protocols: {
    "TLSv1": { status: "rejected" },
    "TLSv1.1": { status: "rejected" },
    "TLSv1.2": { status: "accepted" },
    "TLSv1.3": { status: "accepted" },
  },
  negotiated: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", standardName: "TLS_AES_256_GCM_SHA384" },
  certificate: {
    subject: "example.com", issuer: "R11", notBefore: day(-30), notAfter: day(60), subjectAltNames: ["example.com"],
    hostnameMatches: true, hostnameError: null, selfSigned: false, keyType: "RSA", keyBits: 2048, signatureAlgorithm: "sha256WithRSAEncryption",
  },
  trusted: true,
  trustError: null,
  ...over,
});

// A real logger whose output is captured, so a test reads what was really logged.
const log = () => capturedLog();
const savedLabs = process.env["SSLLABS_ENABLED"];
const scan = () => ({ vulnerabilities: [], tlsGrade: null, tests: [] }) as unknown as ScanResult;

afterEach(() => {
  if (savedLabs === undefined) delete process.env["SSLLABS_ENABLED"];
  else process.env["SSLLABS_ENABLED"] = savedLabs;
});

describe("sslLabsEnabled", () => {
  it("is off unless SSLLABS_ENABLED is exactly 'true'", () => {
    process.env["SSLLABS_ENABLED"] = "";
    expect(sslLabsEnabled()).toBe(false);
    for (const v of ["1", "yes", "TRUE", "false", "on"]) {
      process.env["SSLLABS_ENABLED"] = v;
      expect(sslLabsEnabled(), v).toBe(false);
    }
    process.env["SSLLABS_ENABLED"] = "true";
    expect(sslLabsEnabled()).toBe(true);
  });
});

describe("mergeTlsCheck", () => {
  it("adds the check's findings to the scan and returns them", () => {
    const r = scan();
    const l = log();
    const run = mergeTlsCheck(r, { status: "inspected", result: result({ trusted: false, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT", certificate: { ...result().certificate!, selfSigned: true } }) }, l.log, NOW);
    expect(run.findings.map((f) => f.name)).toEqual(["Self-Signed TLS Certificate"]);
    expect(r.vulnerabilities).toEqual(run.findings);
    expect(r.tlsGrade).toBeNull();
    expect(l.at("info")).toHaveLength(1);
  });

  it("adds nothing when the check was skipped or failed, and says why in the log", () => {
    for (const status of ["skipped", "failed"] as const) {
      const r = scan();
      const l = log();
      const run = mergeTlsCheck(r, { status, reason: "no route" }, l.log, NOW);
      expect(run.findings).toEqual([]);
      expect(r.vulnerabilities).toEqual([]);
      expect(l.at("warn").length + l.at("info").length).toBe(1);
    }
  });
});

describe("tlsCheckRecord", () => {
  const run = (inspection: TlsInspection, findings: TlsCheckRun["findings"] = []): TlsCheckRun => ({ inspection, findings });

  it("records a clean run with a short summary in the name and no letter", () => {
    const rec = tlsCheckRecord(run({ status: "inspected", result: result() }), 120, NOW);
    expect(rec).toEqual({
      group: "transport",
      name: "TLS configuration check (TLS 1.3 negotiated, certificate valid for 60 more days)",
      status: "ran",
      findings: 0,
      durationMs: 120,
    });
    expect(rec.name).not.toMatch(/grade/i);
  });

  it("names the findings it raised, so the check-by-check view can place them", () => {
    const r = scan();
    const merged = mergeTlsCheck(r, { status: "inspected", result: result({ protocols: { ...result().protocols, "TLSv1": { status: "accepted" } } }) }, log().log, NOW);
    const rec = tlsCheckRecord(merged, 5, NOW);
    expect(rec.findings).toBe(1);
    expect(rec.found).toEqual(["Deprecated TLS Protocol Versions Accepted"]);

    const resolved = resolveTest(rec);
    expect(resolved.category).toBe("Transport Security");
    expect(resolved.checks.find((c) => c.name === "Deprecated TLS Protocol Versions Accepted")?.outcome).toBe("finding");
    expect(resolved.checks.find((c) => c.name === "TLS Certificate Expired")?.outcome).toBe("clear");
  });

  it("records a target that is not HTTPS as skipped, with the reason, not as a failure", () => {
    const rec = tlsCheckRecord(run({ status: "skipped", reason: "the target is not served over HTTPS, so there is no TLS to inspect" }), 3, NOW);
    expect(rec).toMatchObject({ name: TLS_CHECK_TEST, status: "skipped", findings: 0, reason: expect.stringMatching(/not served over HTTPS/) });
  });

  it("records a handshake that could not complete as failed, with the reason", () => {
    const rec = tlsCheckRecord(run({ status: "failed", reason: "could not connect to example.com:443: timed out after 8s" }), 8000, NOW);
    expect(rec).toMatchObject({ status: "failed", reason: expect.stringMatching(/timed out/) });
  });

  it("maps to the catalog's TLS test whatever the summary says", () => {
    for (const name of [TLS_CHECK_TEST, `${TLS_CHECK_TEST} (TLS 1.2 negotiated, certificate expired 3 days ago)`]) {
      expect(catalogFor(name)?.test).toBe(TLS_CHECK_TEST);
    }
  });
});

describe("recordSideTests: what the report lists", () => {
  async function record(over: { enabled: boolean; sslLabs?: Parameters<typeof recordSideTests>[0]["sslLabsResult"] }): Promise<TestRecord[]> {
    const added: TestRecord[] = [];
    return recordSideTests({
      scanResult: scan(),
      sslLabsEnabled: over.enabled,
      sslLabsResult: over.sslLabs ?? null,
      tlsCheck: { inspection: { status: "inspected", result: result() }, findings: [] },
      reconRunResult: null,
      allowActiveProbes: false,
      parallelStartedAt: Date.now(),
      live: { add: (t) => { added.push(t); }, finish: async () => {} },
      log: log().log,
    });
  }

  it("with SSL Labs off (the default), shows the TLS check and no SSL Labs line, failed or otherwise", async () => {
    const tests = await record({ enabled: false });
    expect(tests.some((t) => /ssl labs/i.test(t.name))).toBe(false);
    expect(tests.find((t) => t.name.startsWith(TLS_CHECK_TEST))?.status).toBe("ran");
    expect(tests.some((t) => t.status === "failed" && t.group === "transport")).toBe(false);
  });

  it("with SSL Labs on and no answer from it, still shows the TLS check, and the SSL Labs line says it returned nothing", async () => {
    const tests = await record({ enabled: true });
    expect(tests.find((t) => t.name.startsWith(TLS_CHECK_TEST))?.status).toBe("ran");
    const labs = tests.find((t) => t.name === "SSL Labs TLS grade");
    expect(labs?.status).toBe("failed");
    expect(labs?.reason).not.toMatch(/basic TLS detection/);
  });

  it("with SSL Labs on and an answer, lists both", async () => {
    const tests = await record({ enabled: true, sslLabs: { grade: "A", hasWarnings: false, isExceptional: false, issues: [], reasons: [], reportUrl: null } });
    expect(tests.map((t) => t.name)).toEqual(expect.arrayContaining(["SSL Labs TLS grade (A)"]));
    expect(tests.some((t) => t.name.startsWith(TLS_CHECK_TEST))).toBe(true);
  });
});
