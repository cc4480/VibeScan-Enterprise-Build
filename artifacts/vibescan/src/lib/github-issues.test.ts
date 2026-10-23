import { describe, it, expect } from "vitest";
import { issueView, safeIssueHref, issueRefusal, destinationFormError, autoFileNote, type GithubIssueDestination } from "./github-issues";

const connected: GithubIssueDestination = { configured: true, repo: "acme/website", available: true };
const unconfigured: GithubIssueDestination = { configured: false, repo: null, available: true };
const ISSUE = { issueNumber: 42, issueUrl: "https://github.com/acme/website/issues/42" };

describe("issueView", () => {
  it("shows nothing until the server has answered, or when it cannot store a token", () => {
    expect(issueView({ destination: undefined, filed: undefined, starting: false })).toEqual({ kind: "hidden" });
    expect(issueView({ destination: { configured: false, repo: null, available: false }, filed: undefined, starting: false })).toEqual({ kind: "hidden" });
  });

  it("offers to connect a repository when none is connected", () => {
    const v = issueView({ destination: unconfigured, filed: undefined, starting: false });
    expect(v.kind).toBe("connect");
  });

  it("offers to create an issue in the connected repository, and says where it goes", () => {
    const v = issueView({ destination: connected, filed: undefined, starting: false });
    expect(v).toMatchObject({ kind: "create", label: "Create GitHub issue", busy: false });
    expect((v as { detail: string }).detail).toContain("acme/website");
  });

  it("is busy while the issue is being created", () => {
    expect(issueView({ destination: connected, filed: undefined, starting: true })).toMatchObject({ kind: "create", busy: true, label: "Creating the issue…" });
  });

  it("links to the issue that already exists, instead of offering another", () => {
    expect(issueView({ destination: connected, filed: ISSUE, starting: false })).toEqual({
      kind: "filed", label: "Issue #42 on GitHub", href: "https://github.com/acme/website/issues/42",
    });
  });

  it("does not turn a link that is not a GitHub page into an href", () => {
    const bad = { issueNumber: 7, issueUrl: "https://evil.example/acme/website/issues/7" };
    expect(issueView({ destination: connected, filed: bad, starting: false }).kind).toBe("create");
  });
});

describe("safeIssueHref", () => {
  it.each([
    ["https://github.com/acme/website/issues/1", true],
    ["https://github.example.github.com/x", true],
    ["http://github.com/acme/website/issues/1", false],
    ["javascript:alert(1)", false],
    ["https://github.com.evil.example/x", false],
    ["https://notgithub.com/x", false],
    ["not a url", false],
    ["", false],
  ])("%s -> %s", (url, ok) => {
    expect(safeIssueHref(url) !== null).toBe(ok);
  });
});

describe("issueRefusal", () => {
  it("uses the server's own words, with a fallback", () => {
    expect(issueRefusal({ data: { error: "The token cannot create issues in acme/website." } })).toBe("The token cannot create issues in acme/website.");
    expect(issueRefusal(new Error("boom"))).toBe("That did not work. Please try again.");
    expect(issueRefusal(null)).toBe("That did not work. Please try again.");
    expect(issueRefusal({ data: { error: 42 } })).toBe("That did not work. Please try again.");
  });
});

describe("destinationFormError", () => {
  const token = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0";
  it("accepts a repository in the shapes people paste, and a whole token", () => {
    for (const repo of ["acme/website", " acme/website ", "https://github.com/acme/website", "https://github.com/acme/website.git"]) {
      expect(destinationFormError(repo, token), repo).toBeNull();
    }
  });
  it("explains a repository that is not owner/name", () => {
    for (const repo of ["", "acme", "acme/", "https://gitlab.com/acme/website", "acme/web site"]) {
      expect(destinationFormError(repo, token), repo).toMatch(/owner\/name/);
    }
  });
  it("explains a token that is empty, short or has stray characters", () => {
    for (const t of ["", "short", "has spaces in the token it is long enough", "github_pat_ä" + "x".repeat(30)]) {
      expect(destinationFormError("acme/website", t), t).toMatch(/whole token/);
    }
  });
});

describe("autoFileNote", () => {
  it("names the repository, the level, and the limits the server enforces", () => {
    const note = autoFileNote("acme/website", "high");
    expect(note).toContain("acme/website");
    expect(note).toContain("high and critical");
    expect(note).toMatch(/at most 10 a scan/);
    expect(note).toMatch(/secrets/);
  });

  it("words each level it offers", () => {
    expect(autoFileNote("a/b", "critical")).toContain("critical only");
    expect(autoFileNote("a/b", "medium")).toContain("medium and above");
  });
});
