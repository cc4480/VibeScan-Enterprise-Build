import { describe, it, expect } from "vitest";
import { assessDeepHealth, QUEUE_STALL_MS, PULSE_STALE_MS } from "./health";

const now = new Date("2026-09-26T12:00:00Z");
const minutesAgo = (m: number) => new Date(now.getTime() - m * 60_000);
const healthy = { dbOk: true, stalledScans: 0, activeMonitors: 10, lastPulseAt: minutesAgo(20), now };

describe("assessDeepHealth — what the uptime monitor alerts on", () => {
  it("is ok when the database answers and the worker is keeping up", () => {
    expect(assessDeepHealth(healthy)).toMatchObject({ ok: true, checks: { database: "ok", worker: "ok" }, problems: [] });
  });

  it("fails when the database is down", () => {
    const h = assessDeepHealth({ ...healthy, dbOk: false });
    expect(h.ok).toBe(false);
    expect(h.checks.database).toBe("down");
  });

  it("fails when scans sit queued with no worker picking them up", () => {
    const h = assessDeepHealth({ ...healthy, stalledScans: 2 });
    expect(h.ok).toBe(false);
    expect(h.checks.worker).toBe("stalled");
    expect(h.problems[0]).toMatch(/2 scans have waited over 10 minutes/);
  });

  it("fails when the hourly monitor check goes quiet", () => {
    const h = assessDeepHealth({ ...healthy, lastPulseAt: minutesAgo(PULSE_STALE_MS / 60000 + 5) });
    expect(h.ok).toBe(false);
    expect(h.problems[0]).toMatch(/No hourly monitor check for 95 minutes/);
  });

  it("does not judge the pulse when nothing is being monitored", () => {
    expect(assessDeepHealth({ ...healthy, activeMonitors: 0, lastPulseAt: null }).ok).toBe(true);
  });

  it("fails when sites are monitored but no check has ever run", () => {
    expect(assessDeepHealth({ ...healthy, lastPulseAt: null }).ok).toBe(false);
  });

  it("uses a 10-minute queue stall and a 90-minute pulse window", () => {
    expect(QUEUE_STALL_MS).toBe(10 * 60_000);
    expect(PULSE_STALE_MS).toBe(90 * 60_000);
  });
});
