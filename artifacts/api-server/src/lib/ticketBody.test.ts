import { describe, it, expect } from "vitest";
import { jiraDescription, jiraPriority, linearPriority } from "./ticketBody";
import { parseJiraSite } from "./ticketEndpoints";

describe("parseJiraSite", () => {
  it.each([
    ["acme.atlassian.net", "acme.atlassian.net"],
    ["ACME.atlassian.net", "acme.atlassian.net"],
    ["https://acme.atlassian.net/jira/software/projects/SEC", "acme.atlassian.net"],
    ["acme", "acme.atlassian.net"],
    ["  acme-corp  ", "acme-corp.atlassian.net"],
  ])("reads %s", (input, site) => expect(parseJiraSite(input)).toBe(site));

  it.each([
    "evil.example.com", "acme.atlassian.net.evil.com", "http://acme.atlassian.net", "acme.atlassian.net:8443", "user@acme.atlassian.net",
    "-acme.atlassian.net", "", "169.254.169.254", "127.0.0.1", "a b",
  ])("refuses %s", (input) => expect(parseJiraSite(input)).toBeNull());

  it("only ever produces an atlassian.net host, whatever the shorthand", () => {
    expect(parseJiraSite("localhost")).toBe("localhost.atlassian.net");
  });
});

describe("priorities", () => {
  it("maps severities to Linear's 1 to 4 and Jira's standard names", () => {
    expect(["critical", "high", "medium", "low", "info"].map(linearPriority)).toEqual([1, 2, 3, 4, 0]);
    expect(["Critical", "HIGH", "medium", "low", "info"].map(jiraPriority)).toEqual(["Highest", "High", "Medium", "Low", null]);
  });
});

describe("jiraDescription", () => {
  const finding = { id: "f", name: "Exposed .env", severity: "critical", category: "Information Disclosure", description: "First.\n\nSecond @octocat <b>x</b>.", evidence: "DB=postgres://user:hunter2hunter2@db/x\nJWT_SECRET=Zq8vK2mT9xW4pL7cRn5Bd3Hy", solution: "Remove it." };
  const doc = jiraDescription(finding, { targetUrl: "https://shop.example.com/", reportUrl: "https://secscan.us/report/abc" });

  it("is a version 1 document whose every text node is non-empty", () => {
    expect(doc).toMatchObject({ type: "doc", version: 1 });
    const walk = (n: { text?: string; content?: unknown[] }): string[] => (n.text !== undefined ? [n.text] : (n.content ?? []).flatMap((c) => walk(c as never)));
    for (const t of walk(doc as never)) expect(t).not.toBe("");
  });

  it("splits paragraphs, keeps the evidence in a code block, and links the report", () => {
    const json = JSON.stringify(doc);
    expect(json).toContain('"text":"First."');
    expect(json).toContain('"text":"Second @octocat <b>x</b>."'); // text, not markup and not a mention node
    expect(json).toContain('"type":"codeBlock"');
    expect(json).toContain('"href":"https://secscan.us/report/abc"');
    expect(json).not.toContain('"type":"mention"');
  });

  it("redacts secrets", () => {
    const json = JSON.stringify(doc);
    expect(json).not.toContain("Zq8vK2mT9xW4pL7cRn5Bd3Hy");
    expect(json).not.toContain("hunter2hunter2");
    expect(json).toContain("JWT_SECRET=<redacted>");
  });

  it("copes with a finding that has nothing but a name", () => {
    const bare = jiraDescription({ id: "f", name: "n", severity: "low", category: "", description: "" }, { targetUrl: "https://x.test/", reportUrl: "https://secscan.us/report/1" });
    expect(JSON.stringify(bare)).toContain("No description.");
    expect(JSON.stringify(bare)).not.toContain("codeBlock");
  });
});
