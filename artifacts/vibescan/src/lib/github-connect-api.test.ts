import { describe, it, expect } from "vitest";
import { connectOutcomeMessage, connectionNote, repoFieldValue } from "./github-connect-api.js";

describe("connectOutcomeMessage", () => {
  it("confirms a successful connection", () => {
    expect(connectOutcomeMessage("?github=connected")).toMatchObject({ tone: "good" });
  });

  it("explains each way it can fall short, and that nothing was saved where that is so", () => {
    expect(connectOutcomeMessage("?github=none")!.text).toMatch(/choose the repositories to share/);
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

describe("connectionNote", () => {
  const c = (over: object) => ({ installationId: 7, accountLogin: "alice", ...over });

  it("says nothing about a connection that is working", () => {
    expect(connectionNote(c({ status: "ok", repositoryCount: 3 }))).toBeNull();
    expect(connectionNote(c({}))).toBeNull(); // an older server that sends no status
  });

  it("tells an uninstalled App from an unreachable GitHub from nothing shared, each with its own fix", () => {
    expect(connectionNote(c({ status: "gone" }))).toMatch(/uninstalled from alice.*connect again/);
    expect(connectionNote(c({ status: "unavailable" }))).toMatch(/could not be reached.*Try again/);
    expect(connectionNote(c({ status: "ok", repositoryCount: 0 }))).toMatch(/no repository is shared/);
  });

  it("names the installation when GitHub gave no account name", () => {
    expect(connectionNote(c({ accountLogin: null, status: "gone" }))).toContain("installation 7");
  });
});
