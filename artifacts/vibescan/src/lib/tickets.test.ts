import { describe, it, expect } from "vitest";
import { destinationLabel, jiraFormError, linearFormError, safeTicketHref, ticketAutoNote, ticketViews, type TicketDestination } from "./tickets";

const linear: TicketDestination = { provider: "linear", target: "ENG", site: null, accountEmail: null, issueType: null, autoFile: false, autoMinSeverity: "high" };
const jira: TicketDestination = { provider: "jira", target: "SEC", site: "acme.atlassian.net", accountEmail: "dev@acme.com", issueType: "Task", autoFile: true, autoMinSeverity: "critical" };

describe("safeTicketHref", () => {
  it("allows Linear and Jira Cloud pages over https only", () => {
    expect(safeTicketHref("https://linear.app/acme/issue/ENG-1/x")).toBe("https://linear.app/acme/issue/ENG-1/x");
    expect(safeTicketHref("https://acme.atlassian.net/browse/SEC-1")).toBe("https://acme.atlassian.net/browse/SEC-1");
  });
  it.each([
    "http://linear.app/x", "https://evil.example/linear.app", "https://linear.app.evil.com/x", "https://atlassian.net.evil.com/x", "javascript:alert(1)", "not a url",
  ])("refuses %s", (url) => expect(safeTicketHref(url)).toBeNull());
});

describe("ticketViews", () => {
  it("shows nothing for a system that is not connected", () => {
    expect(ticketViews({ destinations: undefined, filed: undefined, starting: null })).toEqual([]);
    expect(ticketViews({ destinations: [], filed: undefined, starting: null })).toEqual([]);
  });

  it("offers one create control per connected system, saying where it goes", () => {
    const v = ticketViews({ destinations: [linear, jira], filed: undefined, starting: null });
    expect(v.map((x) => [x.kind, x.provider, x.label])).toEqual([
      ["create", "linear", "Create Linear issue"], ["create", "jira", "Create Jira ticket"],
    ]);
    expect((v[0] as { detail: string }).detail).toContain("ENG on Linear");
    expect((v[1] as { detail: string }).detail).toContain("SEC on acme.atlassian.net");
  });

  it("shows the ticket that exists instead of offering another, per system", () => {
    const v = ticketViews({ destinations: [linear, jira], filed: { linear: { ticketKey: "ENG-12", ticketUrl: "https://linear.app/acme/issue/ENG-12" } }, starting: null });
    expect(v[0]).toEqual({ kind: "filed", provider: "linear", label: "ENG-12 on Linear", href: "https://linear.app/acme/issue/ENG-12" });
    expect(v[1]!.kind).toBe("create");
  });

  it("does not turn a link that is not Linear's or Jira's into an href", () => {
    const v = ticketViews({ destinations: [linear], filed: { linear: { ticketKey: "ENG-1", ticketUrl: "https://evil.example/x" } }, starting: null });
    expect(v[0]!.kind).toBe("create");
  });

  it("is busy only for the system being filed in", () => {
    const v = ticketViews({ destinations: [linear, jira], filed: undefined, starting: "jira" });
    expect(v.map((x) => x.kind === "create" && x.busy)).toEqual([false, true]);
  });
});

describe("wording", () => {
  it("names where a destination files", () => {
    expect(destinationLabel(linear)).toBe("ENG on Linear");
    expect(destinationLabel(jira)).toBe("SEC on acme.atlassian.net");
  });
  it("says what the switch does, with the chosen floor and where", () => {
    expect(ticketAutoNote(jira)).toContain("critical only");
    expect(ticketAutoNote(jira)).toContain("SEC on acme.atlassian.net");
    expect(ticketAutoNote(jira)).toContain("at most 10 a scan");
  });
});

describe("form checks", () => {
  const key = "lin_api_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4";
  it("Linear: wants a team key and a whole key", () => {
    expect(linearFormError({ team: "ENG", apiKey: key })).toBeNull();
    expect(linearFormError({ team: "not a team", apiKey: key })).toMatch(/team key/);
    expect(linearFormError({ team: "ENG", apiKey: "short" })).toMatch(/whole API key/);
  });
  const ok = { site: "acme.atlassian.net", email: "dev@acme.com", token: "ATATT3xFfGF0abcdef", project: "SEC", issueType: "" };
  it("Jira: wants a Cloud site, an email, a token and a project key", () => {
    expect(jiraFormError(ok)).toBeNull();
    expect(jiraFormError({ ...ok, site: "acme" })).toBeNull();
    expect(jiraFormError({ ...ok, site: "https://acme.atlassian.net/jira/software" })).toBeNull();
    expect(jiraFormError({ ...ok, site: "evil.example.com" })).toMatch(/Jira Cloud site/);
    expect(jiraFormError({ ...ok, email: "nobody" })).toMatch(/email/);
    expect(jiraFormError({ ...ok, token: "x" })).toMatch(/token/);
    expect(jiraFormError({ ...ok, project: "1" })).toMatch(/project key/);
  });
});
