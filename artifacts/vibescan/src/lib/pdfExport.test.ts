import { describe, it, expect } from "vitest";
import { planPages, type Block } from "./pdfExport";

/** Blocks 100 tall separated by 20 of gap, starting at 20. */
const stack = (n: number, height = 100, gap = 20): Block[] =>
  Array.from({ length: n }, (_, i) => ({ top: 20 + i * (height + gap), bottom: 20 + i * (height + gap) + height }));

describe("planPages: a page ends between blocks, never through one", () => {
  it("puts everything on one page when it fits", () => {
    expect(planPages(stack(3), 380, 1000)).toEqual([{ start: 0, end: 380 }]);
  });

  it("ends each page at the bottom of a whole block", () => {
    const blocks = stack(10); // bottoms at 120, 240, 360 ...
    const pages = planPages(blocks, 1220, 500);
    for (const p of pages.slice(0, -1)) {
      expect(blocks.some((b) => b.bottom === p.end)).toBe(true);
    }
  });

  it("starts the next page at the top of the next block, dropping the gap", () => {
    const blocks = stack(10);
    const pages = planPages(blocks, 1220, 500);
    for (const p of pages.slice(1)) {
      expect(blocks.some((b) => b.top === p.start)).toBe(true);
    }
  });

  it("never cuts through a heading: the torn 'AI Analysis' case", () => {
    // Page limit 300 from 0: blocks end at 120, 240, 360. The third block (240-360) would be
    // cut at 300, so the page must end at 240 and the block starts the next page whole.
    const pages = planPages(stack(5), 620, 300);
    expect(pages[0]).toEqual({ start: 0, end: 240 });
    expect(pages[1]!.start).toBe(260);
  });

  it("covers every block completely, in order, with no overlap", () => {
    const blocks = stack(30);
    const total = 20 + 30 * 120;
    const pages = planPages(blocks, total, 700);
    for (const b of blocks) {
      const holders = pages.filter((p) => p.start <= b.top && p.end >= b.bottom);
      expect(holders.length).toBe(1);
    }
    for (let i = 1; i < pages.length; i++) expect(pages[i]!.start).toBeGreaterThanOrEqual(pages[i - 1]!.end);
    expect(pages[pages.length - 1]!.end).toBe(total);
  });

  it("slices a block taller than a page, since that cannot be avoided", () => {
    const pages = planPages([{ top: 0, bottom: 1500 }], 1500, 600);
    expect(pages).toEqual([
      { start: 0, end: 600 },
      { start: 600, end: 1200 },
      { start: 1200, end: 1500 },
    ]);
  });

  it("copes with no blocks and with an empty element", () => {
    expect(planPages([], 1000, 400)).toEqual([
      { start: 0, end: 400 },
      { start: 400, end: 800 },
      { start: 800, end: 1000 },
    ]);
    expect(planPages([], 0, 400)).toEqual([]);
    expect(planPages(stack(2), 240, 0)).toEqual([]);
  });

  it("always makes progress, so a bad measurement cannot loop", () => {
    const pages = planPages([{ top: 0, bottom: 0.2 }, { top: 5000, bottom: 5001 }], 6000, 500);
    expect(pages.length).toBeLessThan(500);
    for (let i = 1; i < pages.length; i++) expect(pages[i]!.start).toBeGreaterThan(pages[i - 1]!.start);
  });
});
