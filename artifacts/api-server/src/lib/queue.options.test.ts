import { describe, it, expect } from "vitest";
import { SCAN_JOB_OPTIONS } from "./queue";

describe("scan job options", () => {
  it("carry a heartbeat pg-boss accepts (at least 10 seconds), far below the two-hour expiry", () => {
    expect(SCAN_JOB_OPTIONS.heartbeatSeconds).toBeGreaterThanOrEqual(10);
    expect(SCAN_JOB_OPTIONS.heartbeatSeconds).toBeLessThanOrEqual(300);
  });
});
