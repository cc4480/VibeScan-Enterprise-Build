import { describe, it, expect } from "vitest";
import { scannedPagesLabel } from "./scanned-pages-label.js";

describe("scannedPagesLabel", () => {
  it("counts the root page plus the crawled pages", () => {
    expect(scannedPagesLabel(["/a", "/b"], false)).toBe("Scanned 3 pages");
    expect(scannedPagesLabel(["/a", "/b"], undefined)).toBe("Scanned 3 pages");
  });

  it("uses the singular for the root page alone", () => {
    expect(scannedPagesLabel([], false)).toBe("Scanned 1 page");
  });

  it("shows nothing when a bot-protection layer answered, since those were challenge pages", () => {
    expect(scannedPagesLabel(["/a", "/b"], true)).toBeNull();
  });

  it("shows nothing when the report has no page list", () => {
    expect(scannedPagesLabel(null, false)).toBeNull();
    expect(scannedPagesLabel(undefined, false)).toBeNull();
  });
});
