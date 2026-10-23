import { describe, it, expect } from "vitest";

import { LoginBody, MAX_PASSWORD_LENGTH } from "./accountShared";

describe("sign-in body", () => {
  const email = "owner@example.com";

  it("accepts a password at the registration cap", () => {
    expect(LoginBody.safeParse({ email, password: "p".repeat(MAX_PASSWORD_LENGTH) }).success).toBe(true);
  });

  it("refuses a password past the registration cap, so it is never hashed", () => {
    expect(LoginBody.safeParse({ email, password: "p".repeat(MAX_PASSWORD_LENGTH + 1) }).success).toBe(false);
  });

  it("still refuses an empty password", () => {
    expect(LoginBody.safeParse({ email, password: "" }).success).toBe(false);
  });
});
