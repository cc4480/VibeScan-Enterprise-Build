import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const saved: unknown[][] = [];
const state = { failNext: false, gate: null as null | Promise<void> };

vi.mock("@workspace/db", () => ({
  scansTable: { id: "id" },
  db: {
    update: () => ({
      set: (values: { liveTests: unknown[] }) => ({
        where: async () => {
          if (state.gate) await state.gate;
          if (state.failNext) {
            state.failNext = false;
            throw new Error("db down");
          }
          saved.push(values.liveTests);
        },
      }),
    }),
  },
}));
vi.mock("./logger", () => ({ logger: { warn: vi.fn() } }));

import { createLiveProgress } from "./liveProgress";
import { TestLedger, type TestRecord } from "./testLedger";

const rec = (name: string, status: TestRecord["status"] = "ran"): TestRecord => ({
  group: "passive",
  name,
  status,
  findings: 0,
  durationMs: 5,
});

beforeEach(() => {
  saved.length = 0;
  state.failNext = false;
  state.gate = null;
  vi.useFakeTimers();
});
afterEach(() => vi.useRealTimers());

describe("createLiveProgress", () => {
  it("writes a burst of finished tests as one batch, not one write per test", async () => {
    const live = createLiveProgress("scan-1", 700);
    live.add(rec("a"));
    live.add(rec("b"));
    live.add(rec("c"));
    expect(saved).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(700);
    expect(saved).toHaveLength(1);
    expect((saved[0] as TestRecord[]).map((r) => r.name)).toEqual(["a", "b", "c"]);
  });

  it("keeps earlier tests in every later write", async () => {
    const live = createLiveProgress("scan-1", 700);
    live.add(rec("a"));
    await vi.advanceTimersByTimeAsync(700);
    live.add(rec("b"));
    await vi.advanceTimersByTimeAsync(700);
    expect((saved[1] as TestRecord[]).map((r) => r.name)).toEqual(["a", "b"]);
  });

  it("finish() writes what is still waiting, and nothing fires afterwards", async () => {
    const live = createLiveProgress("scan-1", 700);
    live.add(rec("a"));
    await live.finish();
    expect(saved).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(5000);
    expect(saved).toHaveLength(1);
  });

  it("writes nothing for a scan that recorded nothing", async () => {
    const live = createLiveProgress("scan-1", 700);
    await live.finish();
    expect(saved).toHaveLength(0);
  });

  it("swallows a failed write: progress is a display and must never fail the scan", async () => {
    const live = createLiveProgress("scan-1", 700);
    state.failNext = true;
    live.add(rec("a"));
    await expect(live.finish()).resolves.toBeUndefined();
    live.add(rec("b"));
    await live.finish();
    expect((saved.at(-1) as TestRecord[]).map((r) => r.name)).toEqual(["a", "b"]);
  });

  it("never lets a slow write be overtaken by a newer one", async () => {
    const live = createLiveProgress("scan-1", 700);
    let release!: () => void;
    state.gate = new Promise<void>((r) => (release = r));
    live.add(rec("a"));
    await vi.advanceTimersByTimeAsync(700);
    live.add(rec("b"));
    const done = live.finish();
    release();
    await done;
    expect(saved.map((s) => s.length)).toEqual([1, 2]);
  });
});

describe("TestLedger as a live source", () => {
  it("reports tests recorded any way the scanner records them", async () => {
    const heard: string[] = [];
    const ledger = new TestLedger((r) => heard.push(`${r.status}:${r.name}`));

    await ledger.track("passive", "tracked", Promise.resolve([]));
    await ledger.track("passive", "crashes", Promise.reject(new Error("boom"))).catch(() => {});
    ledger.skip("active", "skipped one", "not verified");
    ledger.records.push(rec("pushed directly"));

    expect(heard).toEqual(["ran:tracked", "failed:crashes", "skipped:skipped one", "ran:pushed directly"]);
    expect(ledger.records).toHaveLength(4);
  });

  it("still works with no listener, and derived arrays are plain arrays", () => {
    const ledger = new TestLedger();
    ledger.skip("active", "x", "why");
    expect(ledger.summary()).toEqual({ ran: 0, skipped: 1, failed: 0, total: 1 });
    const filtered = ledger.records.filter((r) => r.status === "skipped");
    expect(filtered).toHaveLength(1);
    expect(filtered.constructor).toBe(Array);
    expect(JSON.parse(JSON.stringify(ledger.records))).toHaveLength(1);
  });
});
