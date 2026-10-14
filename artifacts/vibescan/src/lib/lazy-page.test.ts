import { describe, it, expect } from "vitest";
import { isStaleChunkError } from "./lazy-page";

describe("isStaleChunkError", () => {
  it.each([
    "Failed to fetch dynamically imported module: https://secscan.us/assets/dashboard-abc.js",
    "Importing a module script failed.",
    "error loading dynamically imported module",
    "Loading chunk 12 failed.",
  ])("recognises %s", (message) => expect(isStaleChunkError(new Error(message))).toBe(true));

  it("leaves other errors alone", () => {
    expect(isStaleChunkError(new Error("Cannot read properties of undefined"))).toBe(false);
    expect(isStaleChunkError("Failed to fetch dynamically imported module")).toBe(false);
  });
});
