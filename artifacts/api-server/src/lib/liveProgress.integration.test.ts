/**
 * Live scan progress against a REAL Postgres (BILLING_TEST_DATABASE_URL), with real timers: what a running
 * scan has finished so far is written to the scan row, in batches, and a failed write never fails the scan.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, uniqueEmail } from "./realDb.testkit";
import { TestLedger, type TestRecord } from "./testLedger";

useRealDb();

const rec = (name: string, status: TestRecord["status"] = "ran"): TestRecord => ({ group: "passive", name, status, findings: 0, durationMs: 5 });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** Short enough to keep the suite quick, long enough that a read straight after add() lands inside the window. */
const FLUSH = 400;

dbSuiteOf(describe)("createLiveProgress (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let createLiveProgress: typeof import("./liveProgress").createLiveProgress;
  const scanIds: string[] = [];

  const newScan = async () => {
    const [s] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId: "live-progress", userEmail: uniqueEmail("live"), targetUrl: "https://live.example/", tier: "deep", status: "scanning" })
      .returning({ id: dbMod.scansTable.id });
    scanIds.push(s!.id);
    return s!.id;
  };
  const liveNames = async (id: string) => {
    const [row] = await dbMod.db.select({ t: dbMod.scansTable.liveTests }).from(dbMod.scansTable).where(eq(dbMod.scansTable.id, id));
    return row?.t ? (row.t as TestRecord[]).map((r) => r.name) : null;
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    ({ createLiveProgress } = await import("./liveProgress"));
  }, 60_000);

  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    if (scanIds.length) await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.id, scanIds));
    await dbMod?.pool?.end?.();
  });

  it("writes a burst of finished tests as one batch, not one write per test", async () => {
    const id = await newScan();
    const live = createLiveProgress(id, FLUSH);
    live.add(rec("a"));
    live.add(rec("b"));
    live.add(rec("c"));
    expect(await liveNames(id)).toBeNull(); // nothing written while the batch window is open
    await sleep(FLUSH + 500);
    expect(await liveNames(id)).toEqual(["a", "b", "c"]);
    await live.finish();
  });

  it("keeps earlier tests in every later write", async () => {
    const id = await newScan();
    const live = createLiveProgress(id, FLUSH);
    live.add(rec("a"));
    await sleep(FLUSH + 500);
    expect(await liveNames(id)).toEqual(["a"]);
    live.add(rec("b"));
    await sleep(FLUSH + 500);
    expect(await liveNames(id)).toEqual(["a", "b"]);
    await live.finish();
  });

  it("finish() writes what is still waiting, and nothing fires afterwards", async () => {
    const id = await newScan();
    const live = createLiveProgress(id, FLUSH);
    live.add(rec("a"));
    await live.finish();
    expect(await liveNames(id)).toEqual(["a"]);
    // A write that fired after finish() would show up as a changed row; clear it and see that it stays clear.
    await dbMod.db.update(dbMod.scansTable).set({ liveTests: null }).where(eq(dbMod.scansTable.id, id));
    await sleep(FLUSH + 400);
    expect(await liveNames(id)).toBeNull();
  });

  it("writes nothing for a scan that recorded nothing", async () => {
    const id = await newScan();
    const live = createLiveProgress(id, FLUSH);
    await live.finish();
    expect(await liveNames(id)).toBeNull();
  });

  it("swallows a failed write: progress is a display and must never fail the scan", async () => {
    // A scan id that is not a UUID makes Postgres reject the write, which is a real failure rather than a staged one.
    const live = createLiveProgress("not-a-uuid", FLUSH);
    live.add(rec("a"));
    await expect(live.finish()).resolves.toBeUndefined();
    // And another scan's progress is unaffected by it.
    const id = await newScan();
    const other = createLiveProgress(id, FLUSH);
    other.add(rec("b"));
    await other.finish();
    expect(await liveNames(id)).toEqual(["b"]);
  });

  it("never lets an older write overtake a newer one, however quickly tests arrive", async () => {
    const id = await newScan();
    const live = createLiveProgress(id, 1); // flushes on nearly every add, so writes queue behind each other
    const names: string[] = [];
    for (let i = 0; i < 40; i++) {
      names.push(`t${i}`);
      live.add(rec(`t${i}`));
      if (i % 5 === 0) await sleep(3);
    }
    await live.finish();
    expect(await liveNames(id)).toEqual(names);
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
