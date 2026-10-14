import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The end of a scan job: the report is stored and the scan closed, or, when the report cannot be stored,
 * the scan is failed and refunded. Both paths clear the stored logins; the failure path must never throw
 * out of the job; and nothing that happens after the report is saved may undo it.
 */
const calls: string[] = [];
const updates: Array<Record<string, unknown>> = [];
let insertFails = false;

vi.mock("@workspace/db", () => ({
  db: {
    insert: () => ({
      values: (v: Record<string, unknown>) => ({
        returning: () => {
          calls.push("insert");
          inserted.push(v);
          return insertFails ? Promise.reject(new Error("fk violation")) : Promise.resolve([{ id: "report-1" }]);
        },
      }),
    }),
    update: () => ({ set: (v: Record<string, unknown>) => { updates.push(v); return { where: () => Promise.resolve() }; } }),
  },
  scansTable: { id: "id" },
  reportsTable: {},
}));
vi.mock("drizzle-orm", () => ({ eq: () => ({}) }));
const inserted: Array<Record<string, unknown>> = [];

const verify = vi.hoisted(() => ({ complete: vi.fn(), fail: vi.fn() }));
vi.mock("./verifyFix", () => ({ completeVerification: verify.complete, failVerificationForScan: verify.fail }));
const billing = vi.hoisted(() => ({ refund: vi.fn() }));
vi.mock("./billing", () => ({ refundFailedScan: billing.refund }));
const side = vi.hoisted(() => ({ monitor: vi.fn(), email: vi.fn() }));
vi.mock("./workerMonitor", () => ({ recordMonitorScan: side.monitor }));
vi.mock("./workerEmail", () => ({ sendReportReadyNotification: side.email }));
vi.mock("./workerSideChecks", () => ({ recordSideTests: () => [] }));
vi.mock("./workerReport", () => ({ buildReport: () => ({}) }));

import { persistReport, refundIfPaid } from "./workerPersist";

const log = { info: vi.fn(), error: vi.fn() };
const base = () => ({
  scanId: "scan-1", userId: "user-1", targetUrl: "https://example.com", tier: "deep",
  scanResult: { finalUrl: "https://example.com/final", requestDurationMs: 42, vulnerabilities: [] } as never,
  tests: [] as never, reportData: { summary: {} } as never, riskScore: 12 as never, grade: "B" as never,
  intercepted: false as never, severityCounts: {} as never, executiveSummary: "s" as never,
  log: log as never,
});

beforeEach(() => {
  calls.length = 0; updates.length = 0; inserted.length = 0; insertFails = false;
  vi.clearAllMocks();
  verify.complete.mockResolvedValue("fixed");
  verify.fail.mockResolvedValue(undefined);
  billing.refund.mockResolvedValue(null);
  side.monitor.mockResolvedValue(undefined);
  side.email.mockResolvedValue(undefined);
});

describe("persistReport: the report is saved", () => {
  it("stores the report under the final URL, completes the scan, and clears the stored logins", async () => {
    await persistReport(base());
    expect(inserted[0]).toMatchObject({ scanId: "scan-1", userId: "user-1", targetUrl: "https://example.com/final", tier: "deep", duration: 42, data: { summary: {} } });
    expect(updates).toHaveLength(1);
    expect(updates[0]).toMatchObject({ status: "complete", credentialsEncrypted: null, secondaryCredentialsEncrypted: null });
    expect(updates[0]!["completedAt"]).toBeInstanceOf(Date);
    expect(side.monitor).toHaveBeenCalledTimes(1);
    expect(side.monitor.mock.calls[0]![0]).toMatchObject({ scanId: "scan-1", reportId: "report-1", grade: "B", riskScore: 12 });
    expect(side.email).toHaveBeenCalledTimes(1);
    expect(billing.refund).not.toHaveBeenCalled();
  });

  it("falls back to the requested URL when the scan never learned a final one", async () => {
    await persistReport({ ...base(), scanResult: { finalUrl: "", requestDurationMs: 1, vulnerabilities: [] } as never });
    expect(inserted[0]).toMatchObject({ targetUrl: "https://example.com" });
  });

  it("judges a re-check against the stored report only when the job is one", async () => {
    await persistReport(base());
    expect(verify.complete).not.toHaveBeenCalled();
    await persistReport({ ...base(), verificationId: "ver-1" });
    expect(verify.complete).toHaveBeenCalledWith("ver-1", { summary: {} });
  });

  it("does not undo a saved report when what comes after it fails", async () => {
    verify.complete.mockRejectedValue(new Error("boom"));
    side.monitor.mockRejectedValue(new Error("boom"));
    side.email.mockRejectedValue(new Error("boom"));
    await persistReport({ ...base(), verificationId: "ver-1" });
    expect(updates.map((u) => u["status"])).toEqual(["complete"]);
    expect(billing.refund).not.toHaveBeenCalled();
    expect(verify.fail).not.toHaveBeenCalled();
  });
});

describe("persistReport: the report cannot be stored", () => {
  it("fails the scan, clears the stored logins, fails a pending re-check and refunds, without throwing", async () => {
    insertFails = true;
    billing.refund.mockResolvedValue("credit");
    await expect(persistReport(base())).resolves.toBeUndefined();
    expect(updates).toHaveLength(1);
    expect(updates[0]).toMatchObject({ status: "failed", error: "Failed to save report — please contact support", credentialsEncrypted: null, secondaryCredentialsEncrypted: null });
    expect(verify.fail).toHaveBeenCalledWith("scan-1");
    expect(billing.refund).toHaveBeenCalledWith("scan-1");
    expect(side.monitor).not.toHaveBeenCalled();
    expect(side.email).not.toHaveBeenCalled();
  });

  it("still finishes when the refund itself fails", async () => {
    insertFails = true;
    billing.refund.mockRejectedValue(new Error("stripe down"));
    verify.fail.mockRejectedValue(new Error("x"));
    await expect(persistReport(base())).resolves.toBeUndefined();
    expect(log.error).toHaveBeenCalled();
  });
});

describe("refundIfPaid", () => {
  it("logs what was given back, and nothing when nothing was", async () => {
    billing.refund.mockResolvedValueOnce("credit");
    await refundIfPaid("scan-1", log);
    expect(log.info).toHaveBeenCalledWith({ scanId: "scan-1", refunded: "credit" }, "Refunded the payment for a failed scan");
    log.info.mockClear();
    billing.refund.mockResolvedValueOnce(null);
    await refundIfPaid("scan-1", log);
    expect(log.info).not.toHaveBeenCalled();
  });
});
