import { describe, it, expect } from "vitest";
import {
  toRow,
  toCheckRow,
  flattenItems,
  orderForDisplay,
  revealDelayMs,
  tally,
  progressPercent,
  EXPECTED_TESTS,
  EXPECTED_REPO_STEPS,
  TEST_MS,
  CHECK_MS,
  type LiveCheck,
  type LiveTest,
} from "./scan-terminal";

const test = (over: Partial<LiveTest>): LiveTest => ({
  group: "passive",
  name: "CORS policy",
  status: "ran",
  findings: 0,
  durationMs: 40,
  ...over,
});
const check = (outcome: LiveCheck["outcome"], name = "A check"): LiveCheck => ({ name, severity: "low", outcome });

describe("toRow: every line reflects the test's real outcome", () => {
  it("shows a clean pass only for a test that ran and found nothing", () => {
    expect(toRow(test({}))).toMatchObject({ mark: "✓", tone: "clean", result: "no issues found" });
  });

  it("shows findings, with the right plural", () => {
    expect(toRow(test({ findings: 1 })).result).toBe("1 finding");
    expect(toRow(test({ findings: 3 })).result).toBe("3 findings");
    expect(toRow(test({ findings: 3 })).tone).toBe("finding");
  });

  it("never shows a skipped test as a pass, and says why", () => {
    const row = toRow(test({ status: "skipped", reason: "no second account supplied" }));
    expect(row.tone).toBe("skipped");
    expect(row.mark).not.toBe("✓");
    expect(row.result).toBe("not run: no second account supplied");
  });

  it("turns the ownership skip into what to do about it", () => {
    const reason = "domain not verified for this account (active tests need proof of ownership)";
    expect(toRow(test({ status: "skipped", reason })).result).toBe("not run: verify this domain to run it");
  });

  it("never shows a test that crashed as a pass", () => {
    const row = toRow(test({ status: "failed", reason: "timed out" }));
    expect(row.tone).toBe("failed");
    expect(row.mark).not.toBe("✓");
    expect(row.result).toBe("did not run: timed out");
  });

  it("copes with a missing reason", () => {
    expect(toRow(test({ status: "skipped" })).result).toContain("no reason recorded");
    expect(toRow(test({ status: "failed" })).result).toContain("unknown error");
  });
});

describe("toCheckRow: a check is only ever shown as clear when the server said so", () => {
  it("maps each outcome to its own mark and words", () => {
    expect(toCheckRow(check("clear"))).toMatchObject({ mark: "✓", result: "clear", tone: "clean" });
    expect(toCheckRow(check("finding"))).toMatchObject({ mark: "!", result: "FOUND", tone: "finding" });
    expect(toCheckRow(check("checked"))).toMatchObject({ result: "checked", tone: "neutral" });
    expect(toCheckRow(check("not_run"))).toMatchObject({ mark: "–", result: "not run", tone: "skipped" });
  });

  it("never gives 'checked' or 'not run' the pass mark", () => {
    expect(toCheckRow(check("checked")).mark).not.toBe("✓");
    expect(toCheckRow(check("not_run")).mark).not.toBe("✓");
  });
});

describe("flattenItems: each test, then the checks inside it", () => {
  it("keeps every check under its own test, in order", () => {
    const a = test({ name: "A", checks: [check("clear", "a1"), check("clear", "a2")] });
    const b = test({ name: "B", checks: [] });
    const c = test({ name: "C", checks: [check("finding", "c1")] });
    const items = flattenItems([a, b, c]);
    expect(items.map((i) => (i.kind === "test" ? `T:${i.test.name}` : `c:${i.check.name}`))).toEqual(["T:A", "c:a1", "c:a2", "T:B", "T:C", "c:c1"]);
  });

  it("copes with a test that has no checks field (an older record)", () => {
    expect(flattenItems([test({})])).toHaveLength(1);
  });
});

describe("orderForDisplay: real results first, what was not run after", () => {
  const ran = (name: string) => test({ name });
  const skipped = (name: string) => test({ name, status: "skipped", reason: "x" });
  const failed = (name: string) => test({ name, status: "failed", reason: "boom" });

  it("holds skipped tests back while the scan is running", () => {
    expect(orderForDisplay([skipped("s1"), ran("a"), skipped("s2"), ran("b")], false).map((t) => t.name)).toEqual(["a", "b"]);
  });

  it("lists them after everything that ran once the scan is over, and drops none", () => {
    const tests = [skipped("s1"), ran("a"), failed("f"), skipped("s2"), ran("b")];
    const shown = orderForDisplay(tests, true);
    expect(shown.map((t) => t.name)).toEqual(["a", "f", "b", "s1", "s2"]);
    expect(shown).toHaveLength(tests.length);
  });

  it("keeps a test that failed among the active ones: it is never hidden with the skips", () => {
    expect(orderForDisplay([failed("f")], false).map((t) => t.name)).toEqual(["f"]);
  });
});

describe("tally: the closing numbers always add up to the total", () => {
  const tests = [
    test({ name: "A", checks: [check("clear"), check("clear"), check("finding")] }),
    test({ name: "B", status: "skipped", reason: "x", checks: [check("not_run"), check("not_run")] }),
    test({ name: "C", status: "failed", reason: "boom", checks: [check("not_run")] }),
    test({ name: "D", findings: 1, checks: [check("checked"), check("checked")] }),
  ];

  it("counts each outcome", () => {
    expect(tally(tests, 8)).toMatchObject({ tests: 4, ran: 2, skipped: 1, failed: 1, clear: 2, finding: 1, checked: 2, notRun: 3, unrecorded: 0 });
  });

  it("says so when the recorded tests do not account for every check, instead of hiding the gap", () => {
    const t = tally(tests, 130);
    expect(t.unrecorded).toBe(130 - 8);
    expect(t.clear + t.finding + t.checked + t.notRun + t.unrecorded).toBe(130);
  });

  it("never reports a negative gap", () => {
    expect(tally(tests, 3).unrecorded).toBe(0);
  });
});

describe("revealDelayMs: slow enough to read", () => {
  const testItem = flattenItems([test({})])[0]!;
  const checkItem = flattenItems([test({ checks: [check("clear")] })])[1]!;

  it("shows tests slower than the checks inside them", () => {
    expect(revealDelayMs(testItem, 10)).toBe(TEST_MS);
    expect(revealDelayMs(checkItem, 10)).toBe(CHECK_MS);
    expect(TEST_MS).toBeGreaterThan(CHECK_MS);
  });

  it("stays readable for a normal backlog", () => {
    expect(revealDelayMs(testItem, 200)).toBeGreaterThanOrEqual(600);
    expect(revealDelayMs(checkItem, 200)).toBeGreaterThanOrEqual(120);
  });

  it("only speeds up when a huge backlog would leave the page replaying long after the scan", () => {
    expect(revealDelayMs(testItem, 400)).toBeLessThan(TEST_MS);
    expect(revealDelayMs(checkItem, 400)).toBeGreaterThanOrEqual(60);
  });

  it("shows a full scan (40 tests, 130 checks) in under a minute and a half, and over half a minute", () => {
    let total = 0;
    for (let i = 0; i < 40; i++) total += TEST_MS;
    for (let i = 0; i < 130; i++) total += CHECK_MS;
    expect(total).toBeLessThan(90_000);
    expect(total).toBeGreaterThan(30_000);
  });
});

describe("progressPercent follows what is on screen", () => {
  it("starts low, never claims completion early, and reaches 100 only when complete", () => {
    expect(progressPercent("queued", 0)).toBeLessThan(10);
    expect(progressPercent("scanning", 0)).toBeLessThan(15);
    expect(progressPercent("scanning", EXPECTED_TESTS)).toBeLessThan(100);
    expect(progressPercent("scanning", 500)).toBeLessThanOrEqual(88);
    expect(progressPercent("analyzing", 0)).toBeGreaterThanOrEqual(92);
    expect(progressPercent("analyzing", 500)).toBeLessThan(100);
    expect(progressPercent("complete", 0)).toBe(100);
  });

  it("only moves forward as lines are shown", () => {
    let last = 0;
    for (let n = 0; n <= EXPECTED_TESTS; n++) {
      const p = progressPercent("scanning", n);
      expect(p).toBeGreaterThanOrEqual(last);
      last = p;
    }
  });

  it("shows no progress for a failed scan", () => {
    expect(progressPercent("failed", 30)).toBe(0);
  });
});

describe("repository steps", () => {
  const step = { group: "repository", name: "Reading files (100 of 544)", status: "ran" as const, findings: 0, durationMs: 0, detail: "100 of 544 read, 1.2 MB" };

  it("shows the step's real numbers instead of 'no issues found'", () => {
    expect(toRow(step).result).toBe("100 of 544 read, 1.2 MB");
    expect(toRow(step).tone).toBe("clean");
  });

  it("keeps the finding count first when a step has findings", () => {
    expect(toRow({ ...step, name: "Check: repository secrets", findings: 3, detail: "543 files checked" }).result).toBe("3 findings · 543 files checked");
  });

  it("still says why a check had nothing to look at", () => {
    const skipped = { ...step, status: "skipped" as const, reason: "no matching files in the repository" };
    expect(toRow(skipped).result).toBe("not run: no matching files in the repository");
  });

  it("fits the progress bar to the number of repository steps", () => {
    expect(progressPercent("scanning", EXPECTED_REPO_STEPS, EXPECTED_REPO_STEPS)).toBe(88);
    expect(progressPercent("scanning", 7, EXPECTED_REPO_STEPS)).toBe(49);
  });
});
