import { describe, it, expect } from "vitest";
import { inviteFormError, isViewOnly, joinedOn, memberLabel, monitorFacts, monitorState, signInForInvite, teamRefusal, type SharedMonitor } from "./team";

describe("inviteFormError", () => {
  it("accepts an ordinary address, with or without surrounding space", () => {
    expect(inviteFormError("jane@example.com")).toBeNull();
    expect(inviteFormError("  Jane.Doe+team@Example.co.uk ")).toBeNull();
  });
  it.each(["", "jane", "jane@", "@example.com", "jane@example", "jane @example.com", "a@b.c", "jane@example.com, bob@example.com", "<x>@example.com"])("refuses %j", (v) => {
    expect(inviteFormError(v)).toMatch(/email address/);
  });
});

describe("isViewOnly", () => {
  it("is true only when the server says the caller is a teammate", () => {
    expect(isViewOnly({ access: "team" })).toBe(true);
    expect(isViewOnly({ access: "owner" })).toBe(false);
    for (const v of [undefined, null, {}, "team", { access: "TEAM" }, { access: true }]) expect(isViewOnly(v), String(v)).toBe(false);
  });
});

describe("signInForInvite", () => {
  it("returns to the invitation after signing in, with the token encoded as one value", () => {
    const url = signInForInvite("abc123");
    expect(url).toBe("/sign-in?returnTo=%2Fteam%2Faccept%3Ftoken%3Dabc123");
    const back = new URLSearchParams(url.split("?")[1]).get("returnTo");
    expect(back).toBe("/team/accept?token=abc123");
  });
  it("cannot be made to point off the site", () => {
    expect(new URLSearchParams(signInForInvite("//evil.example/x").split("?")[1]).get("returnTo")).toBe("/team/accept?token=//evil.example/x");
  });
});

describe("teamRefusal", () => {
  it("uses the server's own words, with a fallback", () => {
    expect(teamRefusal({ data: { error: "This invitation is not valid." } })).toBe("This invitation is not valid.");
    expect(teamRefusal(new Error("boom"))).toBe("That did not work. Please try again.");
    expect(teamRefusal(null)).toBe("That did not work. Please try again.");
  });
});

describe("labels", () => {
  it("says whether an invitation has been accepted", () => {
    expect(memberLabel({ status: "pending" })).toBe("Invited, not accepted yet");
    expect(memberLabel({ status: "active" })).toBe("On your team");
  });
  it("words the join date, or says nothing", () => {
    expect(joinedOn("2026-10-03T12:00:00Z")).toBe("Joined 3 Oct 2026");
    expect(joinedOn(null)).toBe("");
    expect(joinedOn("not a date")).toBe("");
  });
});

describe("monitorState and monitorFacts", () => {
  const site = (over: Partial<SharedMonitor> = {}): SharedMonitor => ({
    targetUrl: "https://a.example/", paused: false, grade: "B", lastScanAt: null, nextScanAt: null, reachable: true, lastCheckedAt: null,
    uptime24h: 100, medianResponseMs: 120, certDaysRemaining: 60, regressionCount: 0, cveAlertCount: 0, ...over,
  });

  it("names the state in the order that matters", () => {
    expect(monitorState(site()).label).toBe("Healthy");
    expect(monitorState(site({ reachable: null })).label).toBe("Not checked yet");
    expect(monitorState(site({ regressionCount: 1 })).label).toBe("Needs attention");
    expect(monitorState(site({ cveAlertCount: 2 })).label).toBe("Needs attention");
    expect(monitorState(site({ certDaysRemaining: 14 })).label).toBe("Needs attention");
    expect(monitorState(site({ certDaysRemaining: 15 })).label).toBe("Healthy");
    expect(monitorState(site({ reachable: false, regressionCount: 3 })).label).toBe("Down");
    expect(monitorState(site({ paused: true, reachable: false })).label).toBe("Paused");
  });

  it("lists only the facts that are known, with the right plurals", () => {
    expect(monitorFacts(site({ uptime24h: 99.9, medianResponseMs: 180, certDaysRemaining: 1, regressionCount: 1, cveAlertCount: 2 })))
      .toEqual(["99.9% up in 24 h", "180 ms", "certificate 1 day", "1 regression", "2 CVE alerts"]);
    expect(monitorFacts(site({ uptime24h: null, medianResponseMs: null, certDaysRemaining: null }))).toEqual([]);
  });
});

describe("canFile", () => {
  it("is true for the owner and for an editor on the owner's team, and for nobody else", async () => {
    const { canFile } = await import("./team");
    expect(canFile({ access: "owner" })).toBe(true);
    expect(canFile({ access: "team", role: "editor" })).toBe(true);
    expect(canFile({ access: "team", role: "viewer" })).toBe(false);
    expect(canFile({ access: "team" })).toBe(false);
    for (const v of [undefined, null, {}, "owner", { role: "editor" }, { access: "OWNER" }, { access: "owner-ish", role: "editor" }]) expect(canFile(v), String(v)).toBe(false);
  });
});
