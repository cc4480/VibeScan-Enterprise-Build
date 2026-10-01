import { describe, it, expect } from "vitest";
import { markInterceptedTestsNotRun } from "./scannerCoverage";
import type { TestRecord } from "./testLedger";

describe("markInterceptedTestsNotRun", () => {
  it("turns tests that read the intercepted page into 'not tested on the app', and leaves DNS and mail alone", () => {
    const records: TestRecord[] = [
      { group: "HTTP probes", name: "security.txt", status: "ran", findings: 1, durationMs: 5, found: ["Missing security.txt"] },
      { group: "passive", name: "DNS and email authentication", status: "ran", findings: 2, durationMs: 5, found: ["Missing DMARC"] },
      { group: "active", name: "injection (XSS, SQLi)", status: "failed", findings: 0, durationMs: 5, reason: "timeout" },
      { group: "active", name: "path traversal", status: "skipped", findings: 0, durationMs: 0, reason: "not verified" },
    ];
    markInterceptedTestsNotRun(records, "a sign-in page answered instead of the app");
    expect(records[0]).toEqual({
      group: "HTTP probes", name: "security.txt", status: "skipped", findings: 0, durationMs: 5,
      reason: "not tested on the app: a sign-in page answered instead of the app",
    });
    expect(records[1]!.status).toBe("ran");
    expect(records[2]!.status).toBe("failed");
    expect(records[3]!.reason).toBe("not verified");
  });
});
