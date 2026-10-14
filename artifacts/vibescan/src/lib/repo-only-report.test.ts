import { describe, it, expect } from "vitest";
import { isRepoOnlyReport } from "./repo-only-report";

const tests = [{ name: "GitHub source code secrets", status: "ran", source: { repository: "acme/app" } }];

describe("isRepoOnlyReport", () => {
  it("is true for a repository address whose record names that repository", () => {
    expect(isRepoOnlyReport("https://github.com/acme/app", tests)).toBe(true);
    expect(isRepoOnlyReport("https://github.com/Acme/App/tree/dev", tests)).toBe(true);
  });
  it("is false for a website, even with a repository record", () => {
    expect(isRepoOnlyReport("https://acme.dev", tests)).toBe(false);
  });
  it("is false for another repository's record, or no record", () => {
    expect(isRepoOnlyReport("https://github.com/acme/other", tests)).toBe(false);
    expect(isRepoOnlyReport("https://github.com/acme/app", [])).toBe(false);
    expect(isRepoOnlyReport("https://github.com/acme/app", undefined)).toBe(false);
  });
});
