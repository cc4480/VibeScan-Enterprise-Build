import { describe, it, expect } from "vitest";
import { isDestructiveUrl, partitionDestructive } from "./destructive.js";

const B = "https://app.example";

describe("isDestructiveUrl", () => {
  it.each([
    "/account/delete",
    "/users/1/remove",
    "/api/destroy",
    "/logout",
    "/sign-out",
    "/settings/deactivate",
    "/billing/cancel",
    "/tokens/revoke",
    "/admin/purge",
    "/db/drop",
    "/posts/5/archive",
    "/keys/rotate",
    "/payment/refund",
  ])("skips %s", (path) => {
    expect(isDestructiveUrl(`${B}${path}`)).toBe(true);
  });

  it("catches a verb hidden in the query string", () => {
    // The path alone reads as harmless here.
    expect(isDestructiveUrl(`${B}/account?action=delete`)).toBe(true);
    expect(isDestructiveUrl(`${B}/item?delete=1`)).toBe(true);
  });

  it("catches a percent-encoded verb", () => {
    expect(isDestructiveUrl(`${B}/account?action=%64%65%6C%65%74%65`)).toBe(true);
  });

  it("catches verbs joined to other words", () => {
    expect(isDestructiveUrl(`${B}/doDeleteAll`)).toBe(true);
    expect(isDestructiveUrl(`${B}/bulk_remove_users`)).toBe(true);
  });

  it.each([
    "/dashboard",
    "/reports/123",
    "/settings/profile",
    "/api/v1/scans",
    "/pricing",
    "/search?q=hello",
  ])("allows %s", (path) => {
    expect(isDestructiveUrl(`${B}${path}`)).toBe(false);
  });

  it("treats an unparseable URL as unsafe rather than requesting it", () => {
    expect(isDestructiveUrl("not a url")).toBe(true);
  });

  // The guard is deliberately blunt. This documents the accepted cost: a
  // harmless page is skipped because its name reads as destructive.
  it("over-blocks harmless pages that merely read as destructive", () => {
    expect(isDestructiveUrl(`${B}/blog/how-to-delete-your-data`)).toBe(true);
    expect(isDestructiveUrl(`${B}/help/cancellation-policy`)).toBe(true);
  });
});

describe("partitionDestructive", () => {
  it("separates safe URLs from skipped ones", () => {
    const { safe, skipped } = partitionDestructive([
      `${B}/dashboard`,
      `${B}/account/delete`,
      `${B}/reports`,
      `${B}/logout`,
    ]);
    expect(safe).toEqual([`${B}/dashboard`, `${B}/reports`]);
    expect(skipped).toEqual([`${B}/account/delete`, `${B}/logout`]);
  });

  it("handles an empty list", () => {
    expect(partitionDestructive([])).toEqual({ safe: [], skipped: [] });
  });
});
