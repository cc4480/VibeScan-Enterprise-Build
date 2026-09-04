import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// cveCheck.ts pulls in @workspace/db transitively, which throws at module load
// without DATABASE_URL. pg.Pool connects lazily, so a placeholder that resolves
// nowhere is enough for a pure logging function and touches no network.
process.env["DATABASE_URL"] ||=
  "postgresql://placeholder:placeholder@127.0.0.1:1/placeholder";

const warn = vi.fn();

vi.mock("./logger", () => ({
  logger: { warn, debug: vi.fn(), info: vi.fn(), error: vi.fn() },
}));

const getEolDataFetchedAt = vi.fn<() => Date | null>();

vi.mock("./eolFetcher", () => ({
  getEolDataFetchedAt: () => getEolDataFetchedAt(),
  getLivePhpEol: () => null,
  getLiveNginxEolCycles: () => null,
  getLiveApacheEolCycles: () => null,
}));

/** Every message the logger was warned with, joined for substring matching. */
function warnings(): string {
  return warn.mock.calls.map((c) => String(c[1] ?? "")).join("\n");
}

describe("warnIfLocalDataStale", () => {
  beforeEach(() => {
    warn.mockClear();
    getEolDataFetchedAt.mockReset();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // The regression this file exists for. The nightly endoflife.date job kept
  // the EOL half fresh, and because both halves shared one "effective date",
  // that reset the clock on the hand-maintained CVE tables as well — so the
  // warning that exists to nag about them stayed silent for as long as the
  // daily job kept succeeding.
  it("warns about the hand-maintained tables even when the EOL refresh is fresh", async () => {
    // Bundled tables last reviewed 2026-05-05; well past the 90-day threshold.
    vi.setSystemTime(new Date("2026-09-03T12:00:00Z"));
    getEolDataFetchedAt.mockReturnValue(new Date("2026-09-03T03:00:00Z"));

    const { warnIfLocalDataStale } = await import("./cveCheck.js");
    warnIfLocalDataStale();

    expect(warn).toHaveBeenCalled();
    expect(warnings()).toMatch(/hand-maintained cve tables/i);
    // The EOL half is genuinely fresh, so it must not also complain.
    expect(warnings()).not.toMatch(/EOL data is \d+ days old/i);
  });

  it("warns about EOL data when the nightly job has stopped running", async () => {
    vi.setSystemTime(new Date("2026-09-03T12:00:00Z"));
    getEolDataFetchedAt.mockReturnValue(new Date("2026-01-01T03:00:00Z"));

    const { warnIfLocalDataStale } = await import("./cveCheck.js");
    warnIfLocalDataStale();

    expect(warnings()).toMatch(/EOL data is \d+ days old/i);
  });

  it("stays silent when both halves are inside the threshold", async () => {
    // A date shortly after the bundled review date keeps both halves fresh.
    vi.setSystemTime(new Date("2026-05-20T12:00:00Z"));
    getEolDataFetchedAt.mockReturnValue(new Date("2026-05-20T03:00:00Z"));

    const { warnIfLocalDataStale } = await import("./cveCheck.js");
    warnIfLocalDataStale();

    expect(warn).not.toHaveBeenCalled();
  });
});
