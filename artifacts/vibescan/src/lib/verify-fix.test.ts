import { describe, it, expect } from "vitest";
import { anyPending, refusalMessage, shortDate, viewOf, type VerificationStatus } from "./verify-fix";

const st = (verdict: VerificationStatus["verdict"], completedAt: string | null = "2026-09-26T10:00:00.000Z"): VerificationStatus => ({
  findingId: "f1", verdict, scanId: "s", createdAt: "2026-09-26T09:59:00.000Z", completedAt,
});

describe("viewOf", () => {
  it("offers the check before anything has been asked", () => {
    expect(viewOf(undefined, false)).toMatchObject({ tone: "idle", action: "Check my fix" });
  });

  it("says it is working, and offers nothing, while starting or pending", () => {
    expect(viewOf(undefined, true)).toMatchObject({ tone: "busy", action: null });
    expect(viewOf(st("pending", null), false)).toMatchObject({ tone: "busy", action: null });
    expect(viewOf(st("pending", null), false).detail).toContain("does not use a scan");
  });

  it("calls a finding fixed only for the fixed verdict, and says why", () => {
    const v = viewOf(st("fixed"), false);
    expect(v).toMatchObject({ tone: "good", label: "Fixed and verified (26 Sep)", action: null });
    expect(v.detail).toContain("ran again");
  });

  it("never dresses up 'could not be re-checked' as fixed", () => {
    const v = viewOf(st("not_rechecked"), false);
    expect(v.tone).toBe("neutral");
    expect(v.label).not.toMatch(/fixed/i);
    expect(v.detail).toContain("not confirmed as fixed");
    expect(v.action).toBe("Check again");
  });

  it("is plain about a fix that did not work, and offers another try", () => {
    expect(viewOf(st("still_present"), false)).toMatchObject({ tone: "warn", action: "Check again" });
  });

  it("a failed check changes nothing and offers a retry", () => {
    expect(viewOf(st("failed"), false)).toMatchObject({ tone: "neutral", action: "Try again" });
  });

  it("starting a new check overrides an old verdict", () => {
    expect(viewOf(st("still_present"), true).tone).toBe("busy");
  });
});

describe("helpers", () => {
  it("polls only while something is pending", () => {
    expect(anyPending([st("fixed"), st("pending", null)])).toBe(true);
    expect(anyPending([st("fixed")])).toBe(false);
    expect(anyPending(undefined)).toBe(false);
  });

  it("uses the server's own words for a refusal, with a fallback", () => {
    expect(refusalMessage({ data: { error: "You can check 10 fixes a day." } })).toBe("You can check 10 fixes a day.");
    expect(refusalMessage(new Error("x"))).toBe("That did not start. Please try again.");
    expect(refusalMessage(null)).toBe("That did not start. Please try again.");
  });

  it("formats dates the same everywhere", () => {
    expect(shortDate("2026-09-26T10:00:00.000Z")).toBe("26 Sep");
    expect(shortDate(null)).toBe("");
    expect(shortDate("garbage")).toBe("");
  });
});
