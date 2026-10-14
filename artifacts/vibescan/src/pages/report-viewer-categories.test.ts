import { describe, it, expect } from "vitest";
import { isBulkInformation, BULK_INFO_GROUP } from "./report-viewer-categories";

const v = (severity: string) => ({ severity }) as never;

describe("isBulkInformation", () => {
  it("is true for a long group of information-only findings", () => {
    expect(isBulkInformation(Array.from({ length: BULK_INFO_GROUP + 1 }, () => v("info")))).toBe(true);
  });
  it("is false for a short group", () => {
    expect(isBulkInformation(Array.from({ length: BULK_INFO_GROUP }, () => v("info")))).toBe(false);
  });
  it("is false when any finding is more than information, however long the group", () => {
    expect(isBulkInformation([...Array.from({ length: 30 }, () => v("info")), v("medium")])).toBe(false);
  });
});
