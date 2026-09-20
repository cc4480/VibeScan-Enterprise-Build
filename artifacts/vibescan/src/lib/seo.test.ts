import { describe, it, expect } from "vitest";
import { canonicalFor } from "./seo";

/**
 * The server renders a canonical for whatever URL the browser first asked for,
 * and client-side routing then changes the URL without touching it. Every page
 * reached by a link inside the app therefore carried the entry page's
 * canonical — a saved report page claimed to be /dashboard.
 *
 * What is worth pinning here is the normalisation, because a canonical that
 * disagrees with the server's spelling of the same URL is the duplicate-content
 * signal the tag exists to prevent. The server's rule is in lib/pageMeta.ts:
 * strip the trailing slash, except at the root.
 */
describe("canonicalFor", () => {
  it("builds the canonical for the page being viewed", () => {
    expect(canonicalFor("https://secscan.us", "/learn")).toBe("https://secscan.us/learn");
  });

  it("keeps the root as a bare slash", () => {
    // "https://secscan.us" with no path is a different string to the server's
    // "https://secscan.us/", and two spellings is the thing being avoided.
    expect(canonicalFor("https://secscan.us", "/")).toBe("https://secscan.us/");
  });

  it("strips a trailing slash so it matches the server's spelling", () => {
    expect(canonicalFor("https://secscan.us", "/learn/")).toBe("https://secscan.us/learn");
  });

  it("collapses repeated trailing slashes", () => {
    expect(canonicalFor("https://secscan.us", "/learn///")).toBe("https://secscan.us/learn");
  });

  it("keeps nested paths intact", () => {
    expect(canonicalFor("https://secscan.us", "/report/abc-123")).toBe(
      "https://secscan.us/report/abc-123",
    );
  });

  it("does not double the slash when the origin carries one", () => {
    expect(canonicalFor("https://secscan.us/", "/learn")).toBe("https://secscan.us/learn");
  });
});
