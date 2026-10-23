import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { verifySvixSignature, TIMESTAMP_TOLERANCE_SECONDS } from "./svixSignature";

/**
 * This guards the endpoint that writes the suppression list.
 *
 * If verification can be fooled, anyone who finds the URL can forge a "hard
 * bounce" for any address and permanently stop that person receiving sign-in
 * codes — a denial of service against a named account, no login required, and
 * nothing in the logs that looks out of place. So the cases below are mostly
 * ways a lax implementation would wave a forgery through.
 */

const SECRET = `whsec_${Buffer.from("super-secret-key-material-here").toString("base64")}`;
const ID = "msg_2abc";
const BODY = JSON.stringify({ type: "email.bounced", data: { to: "a@b.co" } });

function sign(secret: string, id: string, ts: string, body: string): string {
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  return createHmac("sha256", key).update(`${id}.${ts}.${body}`).digest("base64");
}

function headersFor(now: Date, body = BODY, secret = SECRET, id = ID) {
  const ts = String(Math.floor(now.getTime() / 1000));
  return { id, timestamp: ts, signature: `v1,${sign(secret, id, ts, body)}` };
}

describe("verifySvixSignature", () => {
  const now = new Date("2026-09-11T12:00:00Z");

  it("accepts a correctly signed payload", () => {
    expect(verifySvixSignature(SECRET, BODY, headersFor(now), now)).toEqual({ ok: true });
  });

  it("accepts when one of several rotated signatures matches", () => {
    const h = headersFor(now);
    const withOld = { ...h, signature: `v1,${sign("whsec_b3RoZXI=", ID, h.timestamp, BODY)} ${h.signature}` };
    expect(verifySvixSignature(SECRET, BODY, withOld, now)).toEqual({ ok: true });
  });

  it("ignores signature versions it does not understand rather than failing", () => {
    const h = headersFor(now);
    expect(
      verifySvixSignature(SECRET, BODY, { ...h, signature: `v2,somethingelse ${h.signature}` }, now),
    ).toEqual({ ok: true });
  });

  // The forgery case. A wrong key must never pass.
  it("rejects a signature made with a different secret", () => {
    const h = headersFor(now, BODY, "whsec_d3Jvbmc=");
    expect(verifySvixSignature(SECRET, BODY, h, now)).toEqual({ ok: false, reason: "no_match" });
  });

  // The tampering case, and the reason the RAW body must be verified rather
  // than a re-serialised parse: change one byte and the signature must fail.
  it("rejects a body altered after signing", () => {
    const h = headersFor(now);
    const tampered = JSON.stringify({ type: "email.bounced", data: { to: "victim@example.com" } });
    expect(verifySvixSignature(SECRET, tampered, h, now)).toEqual({ ok: false, reason: "no_match" });
  });

  it("rejects a signature bound to a different message id", () => {
    const h = headersFor(now);
    expect(verifySvixSignature(SECRET, BODY, { ...h, id: "msg_other" }, now)).toEqual({
      ok: false,
      reason: "no_match",
    });
  });

  // Replay: without a timestamp bound, a captured request stays valid forever
  // and can re-suppress an address the user has since fixed.
  it("rejects a stale payload outside the tolerance window", () => {
    const old = new Date(now.getTime() - (TIMESTAMP_TOLERANCE_SECONDS + 60) * 1000);
    expect(verifySvixSignature(SECRET, BODY, headersFor(old), now)).toEqual({
      ok: false,
      reason: "timestamp_out_of_tolerance",
    });
  });

  it("rejects a timestamp from the future, beyond tolerance", () => {
    const future = new Date(now.getTime() + (TIMESTAMP_TOLERANCE_SECONDS + 60) * 1000);
    expect(verifySvixSignature(SECRET, BODY, headersFor(future), now)).toEqual({
      ok: false,
      reason: "timestamp_out_of_tolerance",
    });
  });

  it("allows ordinary clock drift within the window", () => {
    const skewed = new Date(now.getTime() - (TIMESTAMP_TOLERANCE_SECONDS - 30) * 1000);
    expect(verifySvixSignature(SECRET, BODY, headersFor(skewed), now)).toEqual({ ok: true });
  });

  it("rejects missing headers instead of throwing", () => {
    const h = headersFor(now);
    expect(verifySvixSignature(SECRET, BODY, {}, now)).toEqual({ ok: false, reason: "missing_headers" });
    expect(verifySvixSignature(SECRET, BODY, { id: ID }, now)).toEqual({ ok: false, reason: "missing_headers" });
    expect(verifySvixSignature(SECRET, BODY, { ...h, signature: undefined }, now)).toEqual({
      ok: false,
      reason: "missing_headers",
    });
  });

  it("rejects a non-numeric timestamp instead of treating it as 0", () => {
    const h = headersFor(now);
    expect(verifySvixSignature(SECRET, BODY, { ...h, timestamp: "not-a-number" }, now)).toEqual({
      ok: false,
      reason: "bad_timestamp",
    });
  });

  it("rejects a signature header carrying no v1 entry", () => {
    const h = headersFor(now);
    expect(verifySvixSignature(SECRET, BODY, { ...h, signature: "v9,abc" }, now)).toEqual({
      ok: false,
      reason: "no_signatures",
    });
  });

  // An empty signature must not compare equal to anything.
  it("rejects an empty signature value", () => {
    const h = headersFor(now);
    expect(verifySvixSignature(SECRET, BODY, { ...h, signature: "v1," }, now).ok).toBe(false);
  });
});
