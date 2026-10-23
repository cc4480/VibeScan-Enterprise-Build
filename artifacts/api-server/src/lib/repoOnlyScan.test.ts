import { describe, it, expect } from "vitest";
import { repoOnlyAddress, isRepoOnlyScan } from "./repoOnlyScan";

describe("a scan of a repository alone", () => {
  it.each([
    ["https://github.com/acme/app", "https://github.com/acme/app"],
    ["https://github.com/acme/app/", "https://github.com/acme/app"],
    ["https://www.github.com/acme/app", "https://github.com/acme/app"],
    ["https://github.com/acme/app/tree/dev", "https://github.com/acme/app/tree/dev"],
  ])("recognises %s", (address, expected) => {
    expect(repoOnlyAddress(address)).toBe(expected);
  });

  it.each(["https://acme.dev", "https://github.com", "https://github.com/acme", "https://github.io/acme/app", "https://evil.test/github.com/acme/app"])(
    "leaves %s as an ordinary website",
    (address) => expect(repoOnlyAddress(address)).toBeNull(),
  );

  it("is a stored repository-only scan only when the address and the repository are the same", () => {
    expect(isRepoOnlyScan("https://github.com/acme/app", "https://github.com/acme/app")).toBe(true);
    expect(isRepoOnlyScan("https://github.com/acme/app", null)).toBe(false);
    expect(isRepoOnlyScan("https://acme.dev", "https://github.com/acme/app")).toBe(false);
  });
});
