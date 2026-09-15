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

  it("de-duplicates the same cookie+format via the shared seen set", () => {
    const seen = new Set<string>();
    const a = detectSerializedCookies(["state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"], url, seen);
    const b = detectSerializedCookies(["state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"], url, seen);
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(0);
  });
});
