import { describe, it, expect } from "vitest";
import { chunkPrompt } from "./promptChunks";

const BLANK = "\n\n";
const paras = (n: number, len = 300) =>
  Array.from({ length: n }, (_, i) => `Paragraph ${i}: ` + "word ".repeat(len / 5)).join(BLANK);

describe("chunkPrompt: the AI fix prompt, split for PDF pages", () => {
  it("keeps a short prompt in one piece", () => {
    expect(chunkPrompt("Fix the header.")).toEqual(["Fix the header."]);
  });

  it("returns nothing for an empty prompt", () => {
    expect(chunkPrompt("")).toEqual([]);
    expect(chunkPrompt("   \n\n")).toEqual([]);
  });

  it("never exceeds the size limit", () => {
    for (const piece of chunkPrompt(paras(30), 1000)) expect(piece.length).toBeLessThanOrEqual(1000);
  });

  it("breaks between paragraphs, not through them", () => {
    const pieces = chunkPrompt(paras(12), 900);
    expect(pieces.length).toBeGreaterThan(1);
    for (const piece of pieces) {
      for (const para of piece.split(BLANK)) expect(para).toMatch(/^Paragraph \d+:/);
    }
  });

  it("loses and reorders nothing: joining the pieces gives the original text", () => {
    // Only the outer edges are trimmed; every paragraph between them comes back intact.
    const text = paras(20);
    expect(chunkPrompt(text, 900).join(BLANK)).toBe(text.trim());
  });

  it("breaks an over-long paragraph at line boundaries", () => {
    const text = Array.from({ length: 40 }, (_, i) => `line ${i} of a long block of code`).join("\n");
    const pieces = chunkPrompt(text, 300);
    for (const piece of pieces) expect(piece.length).toBeLessThanOrEqual(300);
    expect(pieces.join("\n")).toContain("line 39 of a long block of code");
  });

  it("hard-wraps a single line longer than the limit rather than dropping it", () => {
    const minified = "a".repeat(3100);
    const pieces = chunkPrompt(minified, 1000);
    expect(pieces.join("")).toBe(minified);
    for (const piece of pieces) expect(piece.length).toBeLessThanOrEqual(1000);
  });
});
