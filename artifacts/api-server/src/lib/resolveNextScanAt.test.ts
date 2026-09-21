import { describe, it, expect } from "vitest";
import { resolveNextScanAt } from "./worker";
import { computeNextScanAt } from "./monitorScheduler";

/**
 * The published cadence — A every 14 days, B/C every 7, D/F every 3 — was
 * never what actually happened.
 *
 * The sweep writes nextScanAt = now + 3 days as a placeholder before
 * enqueueing, so a second sweep tick cannot pick a subscription whose scan is
 * still running. The worker then asked "is the pending time sooner than the
 * grade cadence?" to avoid clobbering the CVE job's deliberate 24-hour
 * follow-up — and 3 days is sooner than 14, so the placeholder won every time.
 * Every A-grade site was rescanned every 3 days: ~5x the intended scanning,
 * ~5x the AI spend, ~5x the traffic at a customer's site, and a claim on
 * secscan.info that had never been true since the cadence shipped.
 *
 * Confirmed live before fixing: a grade-A subscription came back with
 * nextScanAt exactly 3 days out, twice.
 *
 * The eight existing cadence tests all passed throughout, because they test
 * nextScanDelayDays() alone. Nothing tested the two halves together, which is
 * the same gap that hid a dead rate limiter earlier today.
 */

const completedAt = new Date("2026-09-21T23:13:00.000Z");
const after = (ms: number) => new Date(completedAt.getTime() + ms);
const HOURS = 60 * 60 * 1000;
const DAYS = 24 * HOURS;

describe("resolveNextScanAt — the grade cadence must win", () => {
  it("uses the grade cadence when nothing is pending", () => {
    const grade = computeNextScanAt("A", completedAt);
    expect(resolveNextScanAt(null, grade, completedAt)).toEqual(grade);
  });

  it("OVERWRITES the sweep's 3-day placeholder on an A-grade site", () => {
    // The exact bug, with the exact numbers seen in production.
    const grade = computeNextScanAt("A", completedAt);      // +14 days
    const placeholder = after(3 * DAYS);                     // what the sweep wrote

    const result = resolveNextScanAt(placeholder, grade, completedAt);

    expect(result).toEqual(grade);
    expect(result).not.toEqual(placeholder);
    // 14 days, not 3.
    expect(result.getTime() - completedAt.getTime()).toBe(14 * DAYS);
  });

  it("overwrites the placeholder on a B-grade site too", () => {
    const grade = computeNextScanAt("B", completedAt);       // +7 days
    const result = resolveNextScanAt(after(3 * DAYS), grade, completedAt);
    expect(result.getTime() - completedAt.getTime()).toBe(7 * DAYS);
  });

  it("leaves a D/F site at 3 days, which was right by accident before", () => {
    const grade = computeNextScanAt("F", completedAt);       // +3 days
    const result = resolveNextScanAt(after(3 * DAYS), grade, completedAt);
    expect(result.getTime() - completedAt.getTime()).toBe(3 * DAYS);
  });
});

describe("resolveNextScanAt — a real follow-up must still survive", () => {
  it("KEEPS the CVE job's 24-hour re-check", () => {
    // The reason the preserve rule exists. The CVE job sets nextScanAt = +24h
    // before its scan runs; losing that silently drops the re-check that
    // confirms whether a newly matched CVE is actually exploitable.
    const grade = computeNextScanAt("A", completedAt);
    const cveFollowUp = after(24 * HOURS);

    expect(resolveNextScanAt(cveFollowUp, grade, completedAt)).toEqual(cveFollowUp);
  });

  it("keeps a follow-up right up to the 48-hour boundary", () => {
    const grade = computeNextScanAt("A", completedAt);
    const edge = after(48 * HOURS);
    expect(resolveNextScanAt(edge, grade, completedAt)).toEqual(edge);
  });

  it("does not keep one past the boundary", () => {
    // Where a follow-up stops being a follow-up and starts being a placeholder.
    const grade = computeNextScanAt("A", completedAt);
    const tooFar = after(48 * HOURS + 1000);
    expect(resolveNextScanAt(tooFar, grade, completedAt)).toEqual(grade);
  });

  it("ignores a pending time already in the past", () => {
    const grade = computeNextScanAt("A", completedAt);
    expect(resolveNextScanAt(after(-1 * DAYS), grade, completedAt)).toEqual(grade);
  });

  it("never schedules a scan before the one that just finished", () => {
    // The property that matters regardless of the numbers: whatever it
    // returns must be in the future, or the sweep picks it up immediately and
    // the site is rescanned in a loop.
    for (const g of ["A", "B", "C", "D", "F"]) {
      for (const pending of [null, after(-DAYS), after(HOURS), after(3 * DAYS), after(30 * DAYS)]) {
        const result = resolveNextScanAt(pending, computeNextScanAt(g, completedAt), completedAt);
        expect(result.getTime(), `${g} / ${pending?.toISOString() ?? "none"}`)
          .toBeGreaterThan(completedAt.getTime());
      }
    }
  });
});
