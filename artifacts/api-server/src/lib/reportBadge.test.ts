import { describe, it, expect } from "vitest";
import {
  badgeState,
  badgeDate,
  renderBadgeSvg,
  renderMissingBadgeSvg,
  mintBadgeToken,
  isBadgeToken,
  badgeSnippets,
  STALE_AFTER_DAYS,
  scanRanVerified,
  badgeStateForReport,
  NOT_VERIFIED_PREFIX,
} from "./reportBadge";
import { NOT_VERIFIED } from "./testLedger";

const day = 86_400_000;
const scanned = new Date("2026-10-03T12:00:00Z");

describe("badgeState", () => {
  it("shows the grade and the scan date", () => {
    const s = badgeState("B", scanned, new Date(scanned.getTime() + 2 * day));
    expect(s.value).toBe("grade B · Oct 3, 2026");
    expect(s.stale).toBe(false);
  });

  it("goes grey and says so once the scan is older than the stale window", () => {
    // A grade with no age is a claim that never expires; the site may have changed since.
    const s = badgeState("A", scanned, new Date(scanned.getTime() + (STALE_AFTER_DAYS + 1) * day));
    expect(s.stale).toBe(true);
    expect(s.value).toContain("old scan");
    expect(s.color).toBe("#5E6870");
  });

  it("is still fresh on the last day of the window", () => {
    expect(badgeState("A", scanned, new Date(scanned.getTime() + STALE_AFTER_DAYS * day)).stale).toBe(false);
  });

  it("says 'not graded' for the incomplete-coverage sentinel, not a letter", () => {
    // A scan a challenge page answered has no grade; the badge must not invent one.
    expect(badgeState("N/A", scanned, scanned).value).toBe("not graded · Oct 3, 2026");
  });

  it("never echoes a stored grade that is not a single letter A to F", () => {
    // `grade` is read from stored JSON. Anything else must not reach the image.
    for (const bad of ["<script>", "AA", "a", "", null, undefined, 7, { x: 1 }, "F\"/>"]) {
      expect(badgeState(bad, scanned, scanned).value, JSON.stringify(bad)).toBe("not graded · Oct 3, 2026");
    }
  });

  it("gives each letter its own colour", () => {
    const colours = ["A", "B", "C", "D", "F"].map((g) => badgeState(g, scanned, scanned).color);
    expect(new Set(colours).size).toBe(5);
  });
});

describe("badgeDate", () => {
  it("reads in UTC, so the same scan reads the same everywhere", () => {
    expect(badgeDate(new Date("2026-01-01T00:30:00Z"))).toBe("Jan 1, 2026");
    expect(badgeDate(new Date("2026-12-31T23:59:00Z"))).toBe("Dec 31, 2026");
  });
});

describe("renderBadgeSvg", () => {
  it("is a self-contained SVG with an accessible name", () => {
    const svg = renderBadgeSvg(badgeState("A", scanned, scanned));
    expect(svg.startsWith("<svg ")).toBe(true);
    expect(svg).toContain('role="img"');
    expect(svg).toContain('aria-label="SecScan: grade A · Oct 3, 2026"');
    expect(svg).not.toContain("<script");
    expect(svg).not.toContain("href");
  });

  it("escapes everything it is given", () => {
    const svg = renderBadgeSvg({ label: "<b>&", value: `"x" 'y' </text>`, color: "#000", stale: false });
    expect(svg).not.toContain("<b>");
    expect(svg).not.toContain("</text></text>");
    expect(svg).toContain("&lt;b&gt;&amp;");
    expect(svg).toContain("&quot;x&quot; &#39;y&#39; &lt;/text&gt;");
  });

  it("widens the badge to fit longer text", () => {
    const widthOf = (svg: string) => Number(/width="(\d+)"/.exec(svg)![1]);
    const short = renderBadgeSvg(badgeState("A", scanned, scanned));
    const long = renderBadgeSvg(badgeState("A", scanned, new Date(scanned.getTime() + 60 * day)));
    expect(widthOf(long)).toBeGreaterThan(widthOf(short));
  });

  it("renders a visible placeholder for a badge that does not resolve", () => {
    expect(renderMissingBadgeSvg()).toContain("badge not found");
  });
});

describe("badge tokens", () => {
  it("mints a different URL-safe token every time", () => {
    const a = mintBadgeToken();
    const b = mintBadgeToken();
    expect(a).not.toBe(b);
    expect(isBadgeToken(a)).toBe(true);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("rejects anything that is not a token before it reaches the database", () => {
    for (const bad of ["", "short", "has space in it and is long enough", "a/b".repeat(10), "../../etc/passwd", "x".repeat(65), "tok'en".repeat(5)]) {
      expect(isBadgeToken(bad), bad).toBe(false);
    }
  });
});

describe("badgeSnippets", () => {
  it("builds markdown and HTML around the image, linking to the home page and not to a report", () => {
    const s = badgeSnippets("https://secscan.us", "tok123");
    expect(s.imageUrl).toBe("https://secscan.us/api/badge/tok123.svg");
    expect(s.markdown).toBe("[![SecScan grade](https://secscan.us/api/badge/tok123.svg)](https://secscan.us/?ref=badge)");
    expect(s.html).toContain('<img src="https://secscan.us/api/badge/tok123.svg"');
    // A badge is public. It must never link at a share URL, which opens the full report.
    expect(s.markdown).not.toContain("/share/");
    expect(s.html).not.toContain("/share/");
  });
});

describe("scanRanVerified", () => {
  const ran = { group: "active", name: "injection (XSS, SQLi)", status: "ran" };
  const skippedUnverified = { group: "active", name: "path traversal", status: "skipped", reason: NOT_VERIFIED };

  it("is true for a scan whose ledger skipped nothing for want of a verified domain", () => {
    expect(scanRanVerified({ tests: [ran] })).toBe(true);
    // Skipped for another reason is still a verified scan.
    expect(scanRanVerified({ tests: [ran, { name: "GitHub source code secrets", status: "skipped", reason: "no repository was supplied for this scan" }] })).toBe(true);
  });

  it("is false when any test was skipped because the domain was not verified", () => {
    expect(scanRanVerified({ tests: [ran, skippedUnverified] })).toBe(false);
  });

  it("is false for a report with no ledger, an empty one, or no data at all", () => {
    expect(scanRanVerified({ summary: { grade: "A" } })).toBe(false);
    expect(scanRanVerified({ tests: [] })).toBe(false);
    expect(scanRanVerified(null)).toBe(false);
    expect(scanRanVerified("A")).toBe(false);
  });

  it("matches the reason the scanner writes, by its stable prefix", () => {
    // Rewording NOT_VERIFIED without updating NOT_VERIFIED_PREFIX would make every unverified
    // report look verified, and its badge show a grade again. This fails first.
    expect(NOT_VERIFIED.startsWith(NOT_VERIFIED_PREFIX)).toBe(true);
  });
});

describe("badgeStateForReport", () => {
  const now = new Date(scanned.getTime() + 2 * day);

  it("shows the grade for a scan that ran with the domain verified", () => {
    const s = badgeStateForReport({ summary: { grade: "A" }, tests: [{ name: "x", status: "ran" }] }, scanned, now);
    expect(s.value).toBe("grade A · Oct 3, 2026");
  });

  it("shows 'not verified', never the grade, for a scan that skipped the active tests", () => {
    const data = { summary: { grade: "A" }, tests: [{ name: "x", status: "skipped", reason: NOT_VERIFIED }] };
    const s = badgeStateForReport(data, scanned, now);
    expect(s.value).toBe("not verified · Oct 3, 2026");
    expect(s.value).not.toContain("grade");
    expect(s.color).toBe(badgeState("N/A", scanned, now).color);
  });

  it("still marks an old unverified badge as stale", () => {
    const later = new Date(scanned.getTime() + (STALE_AFTER_DAYS + 1) * day);
    expect(badgeStateForReport({ summary: { grade: "A" } }, scanned, later).stale).toBe(true);
  });
});
