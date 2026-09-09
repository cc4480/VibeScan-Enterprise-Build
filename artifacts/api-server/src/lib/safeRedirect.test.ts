import { describe, it, expect } from "vitest";
import { safeReturnTo } from "./safeRedirect";

// This is followed AFTER a successful sign-in, when the victim trusts the page
// they land on, so an escape here is a phishing primitive. Every case below
// escaped one of the two guards this replaced.
describe("safeReturnTo", () => {
  it("keeps ordinary in-app destinations", () => {
    for (const p of ["/", "/dashboard", "/report/abc123", "/scan?x=1", "/learn#top"]) {
      expect(safeReturnTo(p)).toBe(p);
    }
  });

  it("refuses absolute and protocol-relative URLs", () => {
    for (const p of ["https://evil.com", "http://evil.com/x", "//evil.com", "///evil.com"]) {
      expect(safeReturnTo(p)).toBe("/");
    }
  });

  it("refuses forms the URL parser NORMALISES into a protocol-relative URL", () => {
    // The bypasses that defeated `startsWith("//")`: WHATWG rewrites backslash
    // to slash for special schemes, and strips tab/newline/CR outright.
    for (const p of ["/\\evil.com", "/\\\\evil.com", "\\\\evil.com", "/\t/evil.com", "/\n/evil.com", "/\r/evil.com"]) {
      const out = safeReturnTo(p);
      expect(out).toBe("/");
      // Belt and braces: whatever comes back must resolve back to our own origin.
      expect(new URL(out, "https://secscan.us").origin).toBe("https://secscan.us");
    }
  });

  it("refuses non-http schemes", () => {
    for (const p of ["javascript:alert(1)", "data:text/html,<script>1</script>", "file:///etc/passwd"]) {
      expect(safeReturnTo(p)).toBe("/");
    }
  });

  it("refuses anything that is not a usable string", () => {
    for (const v of [undefined, null, "", "   ", 42, {}, [], true]) {
      expect(safeReturnTo(v)).toBe("/");
    }
  });

  it("always returns a rooted same-origin path", () => {
    // The property that actually matters, asserted directly over the cases above.
    for (const p of ["/ok", "//evil.com", "/\\evil.com", "https://evil.com", "javascript:1", ""]) {
      const out = safeReturnTo(p);
      expect(out.startsWith("/")).toBe(true);
      expect(out.startsWith("//")).toBe(false);
      expect(new URL(out, "https://secscan.us").origin).toBe("https://secscan.us");
    }
  });
});
