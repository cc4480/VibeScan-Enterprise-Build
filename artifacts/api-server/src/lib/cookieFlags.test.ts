import { describe, it, expect } from "vitest";
import { parseSetCookie } from "./cookieFlags";

describe("parseSetCookie", () => {
  it("reads flags from attributes only, not from the cookie name or value", () => {
    // A name or value containing "secure"/"httponly"/"samesite" is not the attribute.
    const c = parseSetCookie("secure_session=httponly-samesite; Path=/")!;
    expect(c).toMatchObject({ name: "secure_session", secure: false, httpOnly: false, sameSite: false });
  });
  it("reads real attributes case-insensitively, with or without a value", () => {
    const c = parseSetCookie("sid=abc; Path=/; SECURE; HttpOnly; SameSite=Lax")!;
    expect(c).toMatchObject({ secure: true, httpOnly: true, sameSite: true, deleted: false });
  });
  it("marks a cookie being deleted, by Max-Age or a past Expires", () => {
    expect(parseSetCookie("session=; Max-Age=0; Path=/")!.deleted).toBe(true);
    expect(parseSetCookie("session=x; expires=Thu, 01 Jan 1970 00:00:00 GMT")!.deleted).toBe(true);
  });
  it("does not mark a live cookie as deleted", () => {
    expect(parseSetCookie("session=x; Max-Age=3600")!.deleted).toBe(false);
    expect(parseSetCookie("session=x; Expires=Fri, 01 Jan 2100 00:00:00 GMT")!.deleted).toBe(false);
    expect(parseSetCookie("session=x")!.deleted).toBe(false);
  });
  it("rejects a fragment with no name=value pair", () => {
    expect(parseSetCookie(" 03-Jan-2025 10:00:00 GMT")).toBeNull();
  });
});
