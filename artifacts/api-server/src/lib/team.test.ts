import { describe, it, expect } from "vitest";
import { normalizeEmail, hashInviteToken, inviteUrl, MAX_TEAM, RESEND_AFTER_MS } from "./team";

describe("normalizeEmail", () => {
  it("lower-cases and trims", () => {
    expect(normalizeEmail("  Jane.Doe+team@Example.COM ")).toBe("jane.doe+team@example.com");
  });
  it.each(["", " ", "plain", "a@b", "a@b.c", "@example.com", "a@@example.com", "a b@example.com", "a@exa mple.com", "<x>@example.com", "a@example.com,b@example.com", 'a"b@example.com', "a;b@example.com", 42, null, undefined, {}])(
    "refuses %j",
    (v) => {
      expect(normalizeEmail(v)).toBeNull();
    },
  );
  it("refuses an address longer than 254 characters", () => {
    expect(normalizeEmail(`${"a".repeat(250)}@example.com`)).toBeNull();
  });
});

describe("invitation tokens", () => {
  it("hash to 64 hex characters, the same way every time, and differently for different tokens", () => {
    expect(hashInviteToken("a")).toMatch(/^[0-9a-f]{64}$/);
    expect(hashInviteToken("a")).toBe(hashInviteToken("a"));
    expect(hashInviteToken("a")).not.toBe(hashInviteToken("b"));
  });
  it("link to the accept page with the token in the query", () => {
    expect(inviteUrl("abc")).toMatch(/\/team\/accept\?token=abc$/);
  });
});

describe("limits", () => {
  it("allow ten people and a ten-minute pause between sends", () => {
    expect(MAX_TEAM).toBe(10);
    expect(RESEND_AFTER_MS).toBe(600_000);
  });
});
