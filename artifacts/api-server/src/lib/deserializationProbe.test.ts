import { describe, it, expect } from "vitest";
import { detectSerializedCookies } from "./deserializationProbe";

const url = "https://app.example/";

describe("detectSerializedCookies", () => {
  it("flags a Java serialized object (rO0AB…) in a cookie", () => {
    const f = detectSerializedCookies(["state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA; Path=/"], url, new Set());
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].cweId).toBe("CWE-502");
    expect(f[0].name).toMatch(/Java/);
    expect(f[0].evidence).toMatch(/value redacted/);
  });

  it("flags a PHP serialized object, including URL-encoded", () => {
    const f = detectSerializedCookies([`data=${encodeURIComponent('O:8:"stdClass":0:{}')}`], url, new Set());
    expect(f).toHaveLength(1);
    expect(f[0].name).toMatch(/PHP/);
  });

  it("flags Ruby Marshal and Python pickle cookies", () => {
    const ruby = detectSerializedCookies(["_session=BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiJexampleexample"], url, new Set());
    expect(ruby[0]?.name).toMatch(/Ruby/);
    const pickle = detectSerializedCookies(["blob=gAJ9cQBYBAAAAG5hbWVxAVgFAAAAYWxpY2Vx"], url, new Set());
    expect(pickle[0]?.name).toMatch(/pickle/);
  });

  it("does NOT flag a JWT session cookie", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    expect(detectSerializedCookies([`token=${jwt}`], url, new Set())).toHaveLength(0);
  });

  it("does NOT flag opaque session ids, plain values, or short values", () => {
    expect(detectSerializedCookies(["sid=8f3c1ab29de4f7a1b6c05e2d9f"], url, new Set())).toHaveLength(0);
    expect(detectSerializedCookies(["theme=dark"], url, new Set())).toHaveLength(0);
    expect(detectSerializedCookies(["csrf=aGVsbG8gd29ybGQ"], url, new Set())).toHaveLength(0);
  });

  it("does NOT flag magic bytes buried inside a longer base64 value", () => {
    // The whole basis of the check is that these bytes appear at the START of a
    // serialized value. "BAh" and "gAJ" are three characters, so unanchored they
    // hit inside any sufficiently long analytics or session blob, and a HIGH
    // CWE-502 finding then rests on a coincidence.
    expect(
      detectSerializedCookies(["tracking=Zm9vYmFyBAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiJmV4YW1w"], url, new Set()),
    ).toHaveLength(0);
    expect(
      detectSerializedCookies(["analytics=c29tZXRoaW5nZ0FKOWNRQllCQUFBQUc1aGJXVnhBVmc"], url, new Set()),
    ).toHaveLength(0);
    expect(
      detectSerializedCookies(["blob=YWJjZGVmrO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"], url, new Set()),
    ).toHaveLength(0);
  });

  it("does NOT flag a Fernet token, which decodes to one character off the pickle marker", () => {
    // reddit's `loid` really carries this shape: base64 "Z0FBQUFBQn…" decodes to
    // "gAAAAAB…". A real user's session cookie must not become a HIGH finding.
    const loid = "000000002n5bkfujkr.2.1789847008124.Z0FBQUFBQnFydVhnYmptMVBjb2FHa0pleGFtcGxl";
    expect(detectSerializedCookies([`loid=${loid}`], url, new Set())).toHaveLength(0);
  });

  it("still reports the magic itself as evidence, not the boundary character", () => {
    // A version-prefixed value: the "." is a legitimate boundary, so the marker
    // fires, but the evidence must show the magic and not lead with the dot.
    const f = detectSerializedCookies(
      ["_session=v1.BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiJexampleexample"],
      url,
      new Set(),
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.evidence).toContain("BAh7B0kiD");
    expect(f[0]?.evidence).not.toContain(".BAh");
  });

  it("de-duplicates the same cookie+format via the shared seen set", () => {
    const seen = new Set<string>();
    const a = detectSerializedCookies(["state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"], url, seen);
    const b = detectSerializedCookies(["state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"], url, seen);
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(0);
  });
});
