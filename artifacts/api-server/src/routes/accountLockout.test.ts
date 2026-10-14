import { describe, it, expect, beforeEach } from "vitest";
import { attempts, isLockedOut, recordFailure, MAX_ATTEMPTS } from "./accountShared";

describe("per-account login lockout", () => {
  beforeEach(() => attempts.clear());

  it("locks an account after repeated failures, whatever address they came from", () => {
    const key = "login-acct:victim@example.com";
    for (let i = 0; i < MAX_ATTEMPTS - 1; i++) recordFailure(key);
    expect(isLockedOut(key)).toBe(false);
    recordFailure(key);
    expect(isLockedOut(key)).toBe(true);
  });

  it("looking does not count as a failure", () => {
    for (let i = 0; i < 50; i++) isLockedOut("login-acct:a@example.com");
    expect(isLockedOut("login-acct:a@example.com")).toBe(false);
  });

  it("leaves other accounts alone", () => {
    for (let i = 0; i < MAX_ATTEMPTS; i++) recordFailure("login-acct:a@example.com");
    expect(isLockedOut("login-acct:b@example.com")).toBe(false);
  });
});
