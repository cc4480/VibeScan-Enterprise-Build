import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { unsubscribeToken, verifyUnsubscribeToken, unsubscribeHeaders } from "./emailPrefs";

// A real 32-byte key, since signingKey() decodes ENCRYPTION_KEY as base64.
const TEST_KEY = Buffer.alloc(32, 7).toString("base64");
let saved: string | undefined;

beforeEach(() => {
  saved = process.env.ENCRYPTION_KEY;
  process.env.ENCRYPTION_KEY = TEST_KEY;
});
afterEach(() => {
  if (saved === undefined) delete process.env.ENCRYPTION_KEY;
  else process.env.ENCRYPTION_KEY = saved;
});

describe("unsubscribe tokens", () => {
  it("round-trips the user id it was issued for", () => {
    const id = "8a55c3b2-6f28-4822-97f4-bdc829dd3858";
    expect(verifyUnsubscribeToken(unsubscribeToken(id))).toBe(id);
  });

  it("rejects a token whose signature does not match the id", () => {
    // The attack this prevents: swapping in someone else's id to unsubscribe
    // them. Ids are UUIDs that appear in other URLs, so they are not secret.
    const mine = unsubscribeToken("user-a");
    const theirs = unsubscribeToken("user-b");
    const forged = theirs.split(".")[0] + "." + mine.split(".")[1];
    expect(verifyUnsubscribeToken(forged)).toBeNull();
  });

  it("rejects a tampered signature", () => {
    const t = unsubscribeToken("user-a");
    expect(verifyUnsubscribeToken(t.slice(0, -1) + "X")).toBeNull();
  });

  it("rejects malformed input without throwing", () => {
    for (const bad of ["", ".", "no-dot", "a.b.c.d", "!!!.???"]) {
      expect(verifyUnsubscribeToken(bad)).toBeNull();
    }
  });

  it("does not verify under a different signing key", () => {
    const t = unsubscribeToken("user-a");
    process.env.ENCRYPTION_KEY = Buffer.alloc(32, 9).toString("base64");
    expect(verifyUnsubscribeToken(t)).toBeNull();
  });
});

describe("unsubscribeHeaders", () => {
  it("emits both headers RFC 8058 one-click requires", () => {
    // List-Unsubscribe alone lets a client show a link, but Gmail and Yahoo
    // only render their native control when the -Post header is present too.
    const h = unsubscribeHeaders("https://secscan.us", "user-a");
    expect(h["List-Unsubscribe-Post"]).toBe("List-Unsubscribe=One-Click");
    expect(h["List-Unsubscribe"]).toMatch(
      /^<https:\/\/secscan\.us\/api\/email\/unsubscribe\?token=.+>$/,
    );
  });

  it("does not double the slash when the origin has a trailing one", () => {
    const h = unsubscribeHeaders("https://secscan.us/", "user-a");
    expect(h["List-Unsubscribe"]).not.toContain("secscan.us//");
  });

  it("embeds a token that verifies back to the same user", () => {
    const url = unsubscribeHeaders("https://secscan.us", "user-a")["List-Unsubscribe"]!;
    const token = decodeURIComponent(url.split("token=")[1]!.replace(/>$/, ""));
    expect(verifyUnsubscribeToken(token)).toBe("user-a");
  });
});
