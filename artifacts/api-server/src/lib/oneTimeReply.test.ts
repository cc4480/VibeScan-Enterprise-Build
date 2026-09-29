import { describe, it, expect } from "vitest";
import { classifyReply, type ReplyKind } from "./oneTimeReply";
import type { HttpResult } from "./http";

const reply = (status: number, body: string, type = "application/json"): HttpResult => ({
  status, body, headers: { "content-type": type }, setCookies: [], finalUrl: "https://x/", redirected: false,
});

describe("classifyReply: a 2xx is not automatically a success", () => {
  // Every row was counted as a SUCCESS by the first version's looksLikeSuccess, and five identical
  // concurrent ones raised a HIGH race-condition finding at confidence 90.
  it.each<[string, number, string, ReplyKind]>([
    ["success:false with an error", 200, `{"success":false,"error":"Coupon code is required"}`, "rejected"],
    ["a bare error message", 200, `{"error":"Invalid promo code"}`, "rejected"],
    ["'has already been redeemed'", 200, `{"message":"Coupon has already been redeemed"}`, "rejected"],
    ["valid:false", 200, `{"valid":false}`, "rejected"],
    ["plain text 'not found'", 200, "Code not found", "rejected"],
    ["alreadyClaimed:true", 200, `{"alreadyClaimed":true}`, "rejected"],
    ["'has been used'", 200, `{"error":"Code has been used"}`, "rejected"],
    ["'Not eligible'", 200, `{"error":"Not eligible"}`, "rejected"],
    ["a status field saying failed", 200, `{"status":"failed"}`, "rejected"],
    ["ok:false", 200, `{"ok":false,"reason":"limit reached"}`, "rejected"],
    ["a numeric status of 409 in the body", 200, `{"status":409,"detail":"conflict"}`, "rejected"],
    ["a sign-in page served as HTML", 200, `<html><body><form><input type="password"></form>Sign in</body></html>`, "inconclusive"],
    ["an HTML page detected by content type alone", 200, "welcome", "inconclusive"],
  ])("%s", (label, status, body, expected) => {
    const type = label.includes("content type") ? "text/html; charset=utf-8" : "application/json";
    expect(classifyReply(reply(status, body, type))).toBe(expected);
  });

  it.each<[string, number, string]>([
    ["applied:true", 200, `{"applied":true,"discount":"20%"}`],
    ["ok:true", 200, `{"ok":true}`],
    ["success:true with a friendly message", 200, `{"success":true,"message":"Coupon applied, enjoy 20% off"}`],
    ["an empty errors array", 200, `{"applied":true,"errors":[]}`],
    ["plain text OK", 200, "OK"],
    ["201 created", 201, `{"id":"r_1"}`],
    ["a 204 with no body, which carries no failure signal", 204, ""],
    ["an array of results", 200, `[{"id":1}]`],
  ])("accepts %s", (_label, status, body) => {
    expect(classifyReply(reply(status, body))).toBe("accepted");
  });
});

describe("classifyReply: statuses", () => {
  it.each([400, 401, 403, 404, 405, 409, 410, 422])("treats %i as a clean rejection", (status) => {
    expect(classifyReply(reply(status, `{"error":"no"}`))).toBe("rejected");
  });
  it.each([408, 429, 500, 502, 503])("treats %i as inconclusive: a limit or an outage says nothing about one-time enforcement", (status) => {
    expect(classifyReply(reply(status, "slow down"))).toBe("inconclusive");
  });
  it("treats a redirect as inconclusive", () => {
    expect(classifyReply(reply(302, ""))).toBe("inconclusive");
  });
  it("treats a failed request as inconclusive", () => {
    expect(classifyReply(null)).toBe("inconclusive");
  });
});
