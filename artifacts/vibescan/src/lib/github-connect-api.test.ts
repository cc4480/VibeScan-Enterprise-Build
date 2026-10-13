import { describe, it, expect } from "vitest";
import { connectOutcomeMessage, repoFieldValue } from "./github-connect-api.js";

describe("connectOutcomeMessage", () => {
  it("confirms a successful connection", () => {
    expect(connectOutcomeMessage("?github=connected")).toMatchObject({ tone: "good" });
  });

  it("explains each way it can fall short, and that nothing was saved where that is so", () => {
    expect(connectOutcomeMessage("?github=none")!.text).toMatch(/choose at least one repository/);
    expect(connectOutcomeMessage("?github=expired")!.text).toMatch(/nothing was saved/);
    expect(connectOutcomeMessage("?github=error")!.text).toMatch(/nothing was saved/);
    expect(connectOutcomeMessage("?github=unavailable")!.text).toMatch(/public repository/);
  });

  it("says nothing for a page without an outcome, or one it does not know", () => {
    expect(connectOutcomeMessage("")).toBeNull();
    expect(connectOutcomeMessage("?github=whatever")).toBeNull();
  });
});

describe("repoFieldValue", () => {
  it("is the repository's GitHub address", () => {
    expect(repoFieldValue({ fullName: "me/app", private: true, url: "https://github.com/me/app", installationId: 1 })).toBe("https://github.com/me/app");
  });
});
