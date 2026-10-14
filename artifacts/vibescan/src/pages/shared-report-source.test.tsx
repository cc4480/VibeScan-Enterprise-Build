import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  mostSevere, SourceCodeCard, PrintSourceCode, sourceCodeMarkdown, sourceTestOf, repoFindingsOf, findingFile, isPartial, readSummary, partialNotes,
  SOURCE_TEST_NAME,
} from "./shared-report-source";

const test = (status: "ran" | "skipped" | "failed", extra: object = {}) => ({
  group: "passive", name: SOURCE_TEST_NAME, status, findings: 0, durationMs: 5, ...extra,
});

const CLEAN = test("ran", {
  source: {
    repository: "cc4480/secscan.info", via: "public", read: 12, treeFiles: 140, bytesRead: 90_000,
    checks: [
      { name: "repository secrets", files: 5, findings: 0 },
      { name: "Supabase migrations (RLS and policies)", files: 0, findings: 0, note: "no matching files in the repository" },
    ],
  },
});

const FOUND = test("ran", { findings: 1, source: { repository: "acme/app", via: "github-app", read: 3, checks: [{ name: "repository secrets", files: 2, findings: 1 }] } });
const VULN = { name: "Stripe key (in source repository)", severity: "critical", evidence: "Repository: acme/app\nFile: server/.env\nMatch (redacted): sk_l…" };
const LIVE = { name: "Missing HSTS", severity: "medium", evidence: "Strict-Transport-Security header absent" };

describe("sourceTestOf", () => {
  it("is null when the scan was given no repository, however that was recorded", () => {
    expect(sourceTestOf([test("skipped", { reason: "no repository was supplied for this scan" })])).toBeNull();
    expect(sourceTestOf([])).toBeNull();
    expect(sourceTestOf(undefined)).toBeNull();
    expect(sourceTestOf([{ name: "other", status: "ran", group: "x", findings: 0, durationMs: 1 }])).toBeNull();
  });

  it("is the record when a repository was supplied, read or not", () => {
    expect(sourceTestOf([CLEAN])).toBe(CLEAN);
    const unread = test("skipped", { reason: "private", source: { repository: "acme/app" } });
    expect(sourceTestOf([unread])).toBe(unread);
    expect(sourceTestOf([test("failed", { reason: "rate limit" })])?.status).toBe("failed");
  });
});

describe("helpers", () => {
  it("picks out the findings read from the repository, and their file", () => {
    expect(repoFindingsOf([VULN, LIVE])).toEqual([VULN]);
    expect(repoFindingsOf(null)).toEqual([]);
    expect(findingFile(VULN.evidence)).toBe("server/.env");
    expect(findingFile("nothing here")).toBeNull();
  });

  it("says how much was read and what was left", () => {
    expect(readSummary({ repository: "a/b", read: 1, treeFiles: 9, bytesRead: 2000 })).toBe("Read 1 file (2 KB) of 9 in the repository.");
    expect(isPartial({ repository: "a/b" })).toBe(false);
    expect(isPartial({ repository: "a/b", leftOut: 3 })).toBe(true);
    expect(partialNotes({ repository: "a/b", leftOut: 3, failedReads: 1, truncatedTree: true })).toEqual([
      "3 left out by the file and size limits", "1 could not be downloaded", "GitHub cut the repository's file list short",
    ]);
  });
});

describe("SourceCodeCard", () => {
  it("renders nothing for a scan without a repository", () => {
    expect(renderToStaticMarkup(<SourceCodeCard tests={[test("skipped", { reason: "no repository was supplied for this scan" })]} vulnerabilities={[]} />)).toBe("");
  });

  it("shows the repository, how much was read and each check, for a clean result", () => {
    const html = renderToStaticMarkup(<SourceCodeCard tests={[CLEAN]} vulnerabilities={[LIVE]} />);
    expect(html).toContain("Source code");
    expect(html).toContain("cc4480/secscan.info");
    expect(html).toContain("Read as a public repository");
    expect(html).toContain("Read 12 files");
    expect(html).toContain("repository secrets");
    expect(html).toContain("no matching files in the repository");
    expect(html).toContain("Nothing was found in the files that were read.");
    expect(html).not.toContain("Missing HSTS");
  });

  it("lists what was found, with its file, and says the connection was the GitHub App", () => {
    const html = renderToStaticMarkup(<SourceCodeCard tests={[FOUND]} vulnerabilities={[VULN, LIVE]} />);
    expect(html).toContain("Found in the repository (1)");
    expect(html).toContain("Stripe key (in source repository)");
    expect(html).toContain("server/.env");
    expect(html).toContain("GitHub App");
    expect(html).not.toContain("Missing HSTS");
  });

  it("says a repository that was not read says nothing about its code", () => {
    const html = renderToStaticMarkup(<SourceCodeCard tests={[test("skipped", { reason: "the repository is private", source: { repository: "acme/app" } })]} vulnerabilities={[]} />);
    expect(html).toContain("The repository was not read");
    expect(html).toContain("the repository is private");
    expect(html).toContain("says nothing");
    expect(html).not.toContain("Nothing was found");
  });

  it("warns when part of the repository could not be read", () => {
    const html = renderToStaticMarkup(
      <SourceCodeCard tests={[test("ran", { source: { repository: "a/b", read: 300, leftOut: 40 } })]} vulnerabilities={[]} />,
    );
    expect(html).toContain("Not everything could be read");
    expect(html).toContain("40 left out");
  });
});

describe("print and markdown forms", () => {
  it("print: carries the same facts without collapsing anything", () => {
    const html = renderToStaticMarkup(<PrintSourceCode tests={[FOUND]} vulnerabilities={[VULN]} />);
    expect(html).toContain("Source code: acme/app");
    expect(html).toContain("1 finding from the repository: Stripe key (in source repository).");
    expect(renderToStaticMarkup(<PrintSourceCode tests={[]} vulnerabilities={[]} />)).toBe("");
  });

  it("markdown: a section for a repository, none without one", () => {
    const md = sourceCodeMarkdown([CLEAN], [LIVE]).join("\n");
    expect(md).toContain("## Source code: cc4480/secscan.info");
    expect(md).toContain("- repository secrets: 5 files read, 0 findings");
    expect(md).toContain("Nothing was found in the files that were read.");
    expect(sourceCodeMarkdown([], [])).toEqual([]);
    expect(sourceCodeMarkdown([FOUND], [VULN]).join("\n")).toContain("Stripe key (in source repository) (server/.env)");
  });
});

describe("a scan from before the report kept what was read", () => {
  const OLD_RAN = test("ran");
  const OLD_PRIVATE = test("skipped", { reason: "the repository is private or does not exist (only public repositories can be read)" });

  it("says the check ran but not what it read, instead of claiming nothing was found", () => {
    const html = renderToStaticMarkup(<SourceCodeCard tests={[OLD_RAN]} vulnerabilities={[]} />);
    expect(html).toContain("what it read was not recorded");
    expect(html).not.toContain("Nothing was found");
    expect(sourceCodeMarkdown([OLD_RAN], []).join("\n")).toContain("not recorded");
    expect(sourceCodeMarkdown([OLD_RAN], []).join("\n")).not.toContain("Nothing was found");
  });

  it("still shows that a given repository was not read, even without its name recorded", () => {
    expect(sourceTestOf([OLD_PRIVATE])).toBe(OLD_PRIVATE);
    expect(renderToStaticMarkup(<SourceCodeCard tests={[OLD_PRIVATE]} vulnerabilities={[]} />)).toContain("The repository was not read");
  });
});

describe("mostSevere", () => {
  const f = (name: string, severity: string) => ({ name, severity });

  it("lists the most severe first and keeps the scan's order within a severity", () => {
    const got = mostSevere([f("a", "info"), f("b", "medium"), f("c", "info"), f("d", "high")], 3).map((x) => x.name);
    expect(got).toEqual(["d", "b", "a"]);
  });

  it("returns everything when there are fewer than the limit", () => {
    expect(mostSevere([f("a", "info")], 12)).toHaveLength(1);
  });
});
