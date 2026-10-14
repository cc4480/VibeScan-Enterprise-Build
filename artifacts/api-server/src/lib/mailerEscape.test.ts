import { describe, it, expect } from "vitest";
import { buildAccountHtml } from "./mailerAccount";

describe("account email heading", () => {
  it("does not let a name from a sign-in profile inject markup", () => {
    const html = buildAccountHtml(`Welcome, <img src=x onerror=alert(1)>`, "body", "Go", "https://secscan.us", "foot");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });
});
