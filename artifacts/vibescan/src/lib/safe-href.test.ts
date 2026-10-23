import { describe, it, expect } from "vitest";
import { safeHref } from "./safe-href";

describe("safeHref", () => {
  it("keeps valid https and http addresses", () => {
    expect(safeHref("https://example.com/a?b=1")).toBe("https://example.com/a?b=1");
    expect(safeHref("http://127.0.0.1:5000/x")).toBe("http://127.0.0.1:5000/x");
  });

  it("drops javascript: addresses, in any case or with padding", () => {
    expect(safeHref("javascript:alert(1)")).toBeUndefined();
    expect(safeHref("JavaScript:alert(1)")).toBeUndefined();
    expect(safeHref("  javascript:alert(1)")).toBeUndefined();
  });

  it("drops data: and other non-web addresses", () => {
    expect(safeHref("data:text/html,<script>alert(1)</script>")).toBeUndefined();
    expect(safeHref("file:///etc/passwd")).toBeUndefined();
    expect(safeHref("vbscript:msgbox(1)")).toBeUndefined();
  });

  it("drops values that are not URLs, and empty values", () => {
    expect(safeHref("example.com")).toBeUndefined();
    expect(safeHref("")).toBeUndefined();
    expect(safeHref(null)).toBeUndefined();
    expect(safeHref(undefined)).toBeUndefined();
  });
});
