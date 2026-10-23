import { describe, it, expect } from "vitest";
import { capturedLog, fieldsOf } from "./captureLog.testkit";
import {
  legacyBearerAllowed,
  parseSunset,
  logLegacyBearerStatus,
  loggableRoute,
  createLegacyBearerReporter,
} from "./legacyBearer";

/**
 * The legacy anonymous bearer is on by default, so its sunset has to be safe to
 * get wrong: an unset or garbled date must leave users working (today's
 * behaviour), a date that has passed must close the path, and the explicit
 * ALLOW_LEGACY_ANONYMOUS_BEARER=false must beat every date. Everything here is
 * driven by an injected environment and clock.
 */

const NOW = new Date("2026-10-05T12:00:00.000Z");

describe("legacyBearerAllowed", () => {
  it("is allowed when nothing is set (today's behaviour)", () => {
    expect(legacyBearerAllowed({}, NOW)).toBe(true);
  });

  it("is allowed before a future sunset", () => {
    expect(legacyBearerAllowed({ LEGACY_BEARER_SUNSET: "2026-12-01" }, NOW)).toBe(true);
    expect(legacyBearerAllowed({ LEGACY_BEARER_SUNSET: "2026-10-05T12:00:01Z" }, NOW)).toBe(true);
  });

  it("is rejected once the sunset has passed", () => {
    expect(legacyBearerAllowed({ LEGACY_BEARER_SUNSET: "2026-10-01" }, NOW)).toBe(false);
    expect(legacyBearerAllowed({ LEGACY_BEARER_SUNSET: "2026-10-05T11:59:59Z" }, NOW)).toBe(false);
  });

  it("closes at the sunset instant itself, and a bare date means the start of that day in UTC", () => {
    const env = { LEGACY_BEARER_SUNSET: "2026-12-01" };
    expect(legacyBearerAllowed(env, new Date("2026-11-30T23:59:59.999Z"))).toBe(true);
    expect(legacyBearerAllowed(env, new Date("2026-12-01T00:00:00.000Z"))).toBe(false);
    expect(legacyBearerAllowed(env, new Date("2027-06-01T00:00:00.000Z"))).toBe(false);
  });

  it("treats an unparseable sunset as unset: the path stays OPEN, it is not 'already sunset'", () => {
    for (const bad of ["soon", "12", "2026-13-01", "2026-02-31", "01/12/2026", "2026-12", "2026-12-01T25:00:00Z", "NaN", "0"]) {
      expect(legacyBearerAllowed({ LEGACY_BEARER_SUNSET: bad }, NOW), bad).toBe(true);
    }
  });

  it("treats an empty or blank sunset as unset", () => {
    expect(legacyBearerAllowed({ LEGACY_BEARER_SUNSET: "" }, NOW)).toBe(true);
    expect(legacyBearerAllowed({ LEGACY_BEARER_SUNSET: "   " }, NOW)).toBe(true);
  });

  it("is rejected by ALLOW_LEGACY_ANONYMOUS_BEARER=false with no sunset at all", () => {
    expect(legacyBearerAllowed({ ALLOW_LEGACY_ANONYMOUS_BEARER: "false" }, NOW)).toBe(false);
  });

  it("lets ALLOW_LEGACY_ANONYMOUS_BEARER=false win over a sunset that has not arrived", () => {
    expect(
      legacyBearerAllowed({ ALLOW_LEGACY_ANONYMOUS_BEARER: "false", LEGACY_BEARER_SUNSET: "2099-01-01" }, NOW),
    ).toBe(false);
  });

  it("lets ALLOW_LEGACY_ANONYMOUS_BEARER=false win over an invalid sunset", () => {
    expect(
      legacyBearerAllowed({ ALLOW_LEGACY_ANONYMOUS_BEARER: "false", LEGACY_BEARER_SUNSET: "garbage" }, NOW),
    ).toBe(false);
  });

  it("does not let ALLOW_LEGACY_ANONYMOUS_BEARER=true reopen a path whose sunset has passed", () => {
    expect(legacyBearerAllowed({ ALLOW_LEGACY_ANONYMOUS_BEARER: "true", LEGACY_BEARER_SUNSET: "2026-01-01" }, NOW)).toBe(false);
  });

  it("reads the switch case-insensitively and ignores spaces, and only 'false' closes it", () => {
    expect(legacyBearerAllowed({ ALLOW_LEGACY_ANONYMOUS_BEARER: " False " }, NOW)).toBe(false);
    expect(legacyBearerAllowed({ ALLOW_LEGACY_ANONYMOUS_BEARER: "FALSE" }, NOW)).toBe(false);
    expect(legacyBearerAllowed({ ALLOW_LEGACY_ANONYMOUS_BEARER: "true" }, NOW)).toBe(true);
    expect(legacyBearerAllowed({ ALLOW_LEGACY_ANONYMOUS_BEARER: "" }, NOW)).toBe(true);
  });

  it("defaults to the real environment and clock", () => {
    const saved = { s: process.env["LEGACY_BEARER_SUNSET"], a: process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"] };
    try {
      delete process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"];
      process.env["LEGACY_BEARER_SUNSET"] = "2000-01-01";
      expect(legacyBearerAllowed()).toBe(false);
      process.env["LEGACY_BEARER_SUNSET"] = "2999-01-01";
      expect(legacyBearerAllowed()).toBe(true);
    } finally {
      if (saved.s === undefined) delete process.env["LEGACY_BEARER_SUNSET"];
      else process.env["LEGACY_BEARER_SUNSET"] = saved.s;
      if (saved.a === undefined) delete process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"];
      else process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"] = saved.a;
    }
  });
});

describe("parseSunset", () => {
  it("accepts ISO dates and timestamps, reading a missing offset as UTC", () => {
    expect(parseSunset("2026-12-01")).toEqual({ state: "set", at: new Date("2026-12-01T00:00:00.000Z") });
    expect(parseSunset("2026-12-01T09:30:00")).toEqual({ state: "set", at: new Date("2026-12-01T09:30:00.000Z") });
    expect(parseSunset("2026-12-01T09:30")).toEqual({ state: "set", at: new Date("2026-12-01T09:30:00.000Z") });
    expect(parseSunset("2026-12-01 09:30:00")).toEqual({ state: "set", at: new Date("2026-12-01T09:30:00.000Z") });
    expect(parseSunset("2026-12-01T09:30:00Z")).toEqual({ state: "set", at: new Date("2026-12-01T09:30:00.000Z") });
    expect(parseSunset("2026-12-01T09:30:00.250Z")).toEqual({ state: "set", at: new Date("2026-12-01T09:30:00.250Z") });
    expect(parseSunset("2026-12-01T09:30:00+02:00")).toEqual({ state: "set", at: new Date("2026-12-01T07:30:00.000Z") });
    expect(parseSunset("  2026-12-01  ")).toEqual({ state: "set", at: new Date("2026-12-01T00:00:00.000Z") });
  });

  it("accepts the last day of a leap February and refuses a day that does not exist", () => {
    expect(parseSunset("2028-02-29").state).toBe("set");
    expect(parseSunset("2027-02-29").state).toBe("invalid");
    expect(parseSunset("2026-04-31").state).toBe("invalid");
  });

  it("refuses what Date.parse would silently accept as something else", () => {
    // Date.parse("12") is 1 December 2001; Date.parse("2026-02-31") is 3 March 2026.
    for (const bad of ["12", "2026-02-31", "December 1, 2026", "1 Dec 2026", "2026/12/01", "1796947200000"]) {
      expect(parseSunset(bad), bad).toEqual({ state: "invalid", raw: bad });
    }
  });

  it("reports unset for undefined and blank", () => {
    expect(parseSunset(undefined)).toEqual({ state: "unset" });
    expect(parseSunset("")).toEqual({ state: "unset" });
  });
});

describe("logLegacyBearerStatus", () => {
  it("logs an error once for an unparseable sunset, and says the path is staying open", () => {
    const c = capturedLog();
    logLegacyBearerStatus(c.log, { LEGACY_BEARER_SUNSET: "next tuesday" }, NOW);
    const errors = c.at("error");
    expect(errors).toHaveLength(1);
    expect(fieldsOf(errors[0]!)).toEqual({ variable: "LEGACY_BEARER_SUNSET", value: "next tuesday" });
    expect(errors[0]!.msg).toMatch(/not an ISO 8601 date/);
    expect(errors[0]!.msg).toMatch(/will NOT be sunset/);
    expect(fieldsOf(c.at("info")[0]!)).toMatchObject({ legacyBearer: "open" });
  });

  it("does not echo an arbitrarily long value", () => {
    const c = capturedLog();
    logLegacyBearerStatus(c.log, { LEGACY_BEARER_SUNSET: "x".repeat(500) }, NOW);
    expect((fieldsOf(c.at("error")[0]!) as { value: string }).value).toHaveLength(64);
  });

  it("is quiet about errors for unset and valid values, and reports the state", () => {
    const unset = capturedLog();
    logLegacyBearerStatus(unset.log, {}, NOW);
    expect(unset.at("error")).toHaveLength(0);
    expect(fieldsOf(unset.at("info")[0]!)).toMatchObject({ legacyBearer: "open" });
    expect(fieldsOf(unset.at("info")[0]!).sunset).toBeUndefined();

    const future = capturedLog();
    logLegacyBearerStatus(future.log, { LEGACY_BEARER_SUNSET: "2026-12-01" }, NOW);
    expect(future.at("error")).toHaveLength(0);
    expect(fieldsOf(future.at("info")[0]!)).toMatchObject({ legacyBearer: "open", sunset: "2026-12-01T00:00:00.000Z" });

    const past = capturedLog();
    logLegacyBearerStatus(past.log, { LEGACY_BEARER_SUNSET: "2026-01-01" }, NOW);
    expect(fieldsOf(past.at("info")[0]!)).toMatchObject({ legacyBearer: "closed", closedBy: "LEGACY_BEARER_SUNSET" });

    const off = capturedLog();
    logLegacyBearerStatus(off.log, { ALLOW_LEGACY_ANONYMOUS_BEARER: "false", LEGACY_BEARER_SUNSET: "2099-01-01" }, NOW);
    expect(fieldsOf(off.at("info")[0]!)).toMatchObject({ legacyBearer: "closed", closedBy: "ALLOW_LEGACY_ANONYMOUS_BEARER" });
  });
});

describe("loggableRoute", () => {
  it("keeps the method and path, and drops the query string", () => {
    expect(loggableRoute("GET", "/api/scans?token=abc")).toBe("GET /api/scans");
  });

  it("keeps UUID ids readable", () => {
    const id = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    expect(loggableRoute("GET", `/api/scans/${id}`)).toBe(`GET /api/scans/${id}`);
  });

  it("masks the credentials that live in share and out-of-band URLs", () => {
    expect(loggableRoute("GET", "/api/share/SECRETSECRET")).toBe("GET /api/share/:token");
    expect(loggableRoute("DELETE", "/api/reports/12/shares/SECRETSECRET")).toBe("DELETE /api/reports/12/shares/:token");
    expect(loggableRoute("GET", "/api/oob/SECRETSECRET/x")).toBe("GET /api/oob/:token/x");
  });

  it("masks any other long opaque segment", () => {
    expect(loggableRoute("GET", `/api/thing/${"a1B2".repeat(10)}`)).toBe("GET /api/thing/:token");
  });

  it("copes with a missing method or path", () => {
    expect(loggableRoute(undefined, undefined)).toBe("? ");
  });
});

describe("createLegacyBearerReporter", () => {
  const U1 = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
  const U2 = "9c858901-8a57-4791-81fe-4c455b099bc9";
  const DAY = 24 * 60 * 60_000;

  function make(extra: { maxEntries?: number; windowMs?: number } = {}) {
    let t = 1_000_000;
    const c = capturedLog();
    const reporter = createLegacyBearerReporter({ log: c.log, now: () => t, ...extra });
    return { reporter, warns: () => c.at("warn"), advance: (ms: number) => void (t += ms) };
  }

  it("logs the first use at warn with the user id and route", () => {
    const { reporter, warns } = make();
    expect(reporter.report(U1, "GET /api/scans")).toBe(true);
    expect(warns()).toHaveLength(1);
    const first = warns()[0]!;
    expect(fieldsOf(first)).toEqual({ event: "legacy_anonymous_bearer", userId: U1, route: "GET /api/scans" });
    expect(first.msg).toMatch(/legacy anonymous bearer/);
  });

  it("stays quiet for the same user id for 24 hours, then logs again", () => {
    const { reporter, warns, advance } = make();
    reporter.report(U1, "GET /a");
    advance(60_000);
    expect(reporter.report(U1, "GET /b")).toBe(false);
    advance(DAY - 60_001);
    expect(reporter.report(U1, "GET /c")).toBe(false);
    expect(warns()).toHaveLength(1);

    advance(1);
    expect(reporter.report(U1, "GET /d")).toBe(true);
    expect(warns()).toHaveLength(2);
    expect(fieldsOf(warns()[1]!)).toMatchObject({ route: "GET /d" });
  });

  it("de-duplicates per user id, not globally", () => {
    const { reporter, warns } = make();
    expect(reporter.report(U1, "GET /a")).toBe(true);
    expect(reporter.report(U2, "GET /a")).toBe(true);
    expect(reporter.report(U1, "GET /a")).toBe(false);
    expect(reporter.report(U2, "GET /a")).toBe(false);
    expect(warns()).toHaveLength(2);
  });

  it("measures the 24 hours from the last LOG, so a busy user is still logged once a day", () => {
    const { reporter, warns, advance } = make();
    reporter.report(U1, "x");
    for (let i = 0; i < 23; i++) {
      advance(60 * 60_000);
      reporter.report(U1, "x");
    }
    expect(warns()).toHaveLength(1);
    advance(60 * 60_000);
    reporter.report(U1, "x");
    expect(warns()).toHaveLength(2);
  });

  it("prunes expired entries, so the Map does not grow without bound", () => {
    const { reporter, advance } = make();
    for (let i = 0; i < 50; i++) reporter.report(`user-${i}`, "x");
    expect(reporter.size()).toBe(50);
    advance(DAY + 1);
    reporter.report("someone-new", "x");
    expect(reporter.size()).toBe(1);
  });

  it("keeps unexpired entries when it prunes", () => {
    const { reporter, advance } = make();
    reporter.report("old", "x");
    advance(DAY - 30 * 60_000);
    reporter.report("recent", "x");
    advance(31 * 60_000);
    reporter.report("trigger", "x");
    // "old" has expired, "recent" has not.
    expect(reporter.size()).toBe(2);
    expect(reporter.report("recent", "x")).toBe(false);
  });

  it("is hard-capped even when nothing has expired", () => {
    const { reporter, warns } = make({ maxEntries: 100 });
    for (let i = 0; i < 1000; i++) reporter.report(`user-${i}`, "x");
    expect(reporter.size()).toBeLessThanOrEqual(100);
    expect(warns()).toHaveLength(1000);
    // The newest are remembered, the oldest were evicted.
    expect(reporter.report("user-999", "x")).toBe(false);
    expect(reporter.report("user-0", "x")).toBe(true);
  });

  it("clear forgets everything", () => {
    const { reporter } = make();
    reporter.report(U1, "x");
    reporter.clear();
    expect(reporter.size()).toBe(0);
    expect(reporter.report(U1, "x")).toBe(true);
  });

  it("logs nothing but the event, the user id and the route", () => {
    const { reporter, warns } = make();
    reporter.report(U1, "GET /api/scans");
    expect(Object.keys(fieldsOf(warns()[0]!)).sort()).toEqual(["event", "route", "userId"]);
  });
});
