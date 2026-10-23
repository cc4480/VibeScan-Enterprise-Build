import { describe, it, expect } from "vitest";
import { packFilename } from "./report-viewer-evidence";

describe("packFilename", () => {
  it("reads the file name the server chose", () => {
    expect(packFilename('attachment; filename="secscan-evidence-shop.example.com-2026-10-23.zip"')).toBe("secscan-evidence-shop.example.com-2026-10-23.zip");
  });
  it("falls back when there is no usable name, and never takes a path", () => {
    expect(packFilename(null)).toBe("secscan-evidence.zip");
    expect(packFilename("attachment")).toBe("secscan-evidence.zip");
    expect(packFilename('attachment; filename="../../evil.zip"')).toBe("secscan-evidence.zip");
    expect(packFilename('attachment; filename="a/b.zip"')).toBe("secscan-evidence.zip");
  });
});
