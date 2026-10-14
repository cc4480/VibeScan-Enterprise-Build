import { describe, it, expect } from "vitest";
import { repoScanAddress } from "./scan-form-repo";

describe("repoScanAddress", () => {
  it.each([
    ["cc4480/seclayer.io2026", "https://github.com/cc4480/seclayer.io2026"],
    ["  acme/app ", "https://github.com/acme/app"],
    ["https://github.com/acme/app", "https://github.com/acme/app"],
    ["http://github.com/acme/app", "https://github.com/acme/app"],
  ])("turns %j into an address", (typed, expected) => expect(repoScanAddress(typed)).toBe(expected));

  it.each(["", "   ", "acme", "https://example.com/acme/app", "acme/app/extra"])("gives null for %j", (typed) => expect(repoScanAddress(typed)).toBeNull());
});
