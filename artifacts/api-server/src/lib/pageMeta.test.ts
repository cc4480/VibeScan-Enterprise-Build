import { describe, it, expect } from "vitest";
import { metaForPath, applyPageMeta } from "./pageMeta";
import { SPA_ROUTES } from "./spaRoutes";

const SHELL = `<!doctype html><html><head>
<title>SecScan — Black-Box Security Scanning for Vibe Coders</title>
<meta name="description" content="Paste a URL and get a report." />
<meta name="robots" content="index, follow" />
<link rel="canonical" href="https://secscan.us/" />
<meta property="og:title" content="SecScan" />
<meta property="og:description" content="Old description." />
<meta property="og:url" content="https://secscan.us/" />
<meta name="twitter:title" content="SecScan" />
<meta name="twitter:description" content="Old twitter description." />
</head><body></body></html>`;

describe("page metadata", () => {
  it("leaves the homepage to its built metadata", () => {
    expect(metaForPath("/")).toBeNull();
  });

  it("gives each indexable page its own canonical instead of the homepage", () => {
    // The bug this fixes: every URL claimed the homepage as canonical, so
    // Google treated them as duplicates and declined to index them.
    for (const [path, expected] of [
      ["/learn", "https://secscan.us/learn"],
      ["/privacy", "https://secscan.us/privacy"],
      ["/terms", "https://secscan.us/terms"],
    ] as const) {
      const html = applyPageMeta(SHELL, metaForPath(path)!);
      expect(html, path).toContain(`<link rel="canonical" href="${expected}" />`);
      expect(html, path).not.toContain('canonical" href="https://secscan.us/"');
    }
  });

  it("keeps indexable pages indexable", () => {
    for (const path of ["/learn", "/privacy", "/terms"]) {
      expect(applyPageMeta(SHELL, metaForPath(path)!), path).toContain('content="index, follow"');
    }
  });

  it("marks every private page noindex", () => {
    // These were all being handed to crawlers as index,follow, contradicting
    // the noindex the client sets only after hydration.
    for (const path of [
      "/dashboard",
      "/scan",
      "/scan/abc123",
      "/monitor",
      "/domains",
      "/settings",
      "/sign-in",
      "/register",
      "/forgot-password",
      "/reset-password",
      "/verify-email",
      "/report/abc123",
      "/share/Xy_9-Zq",
    ]) {
      const meta = metaForPath(path);
      expect(meta, path).not.toBeNull();
      expect(meta!.noindex, path).toBe(true);
      expect(applyPageMeta(SHELL, meta!), path).toContain('content="noindex, nofollow"');
    }
  });

  it("does not leave a trailing slash in the canonical", () => {
    expect(applyPageMeta(SHELL, metaForPath("/privacy/")!)).toContain('href="https://secscan.us/privacy"');
  });

  it("updates og and twitter tags alongside the canonical", () => {
    const html = applyPageMeta(SHELL, metaForPath("/learn")!);
    expect(html).toContain('og:url" content="https://secscan.us/learn"');
    expect(html).toContain('og:title" content="Security Documentation — SecScan"');
    expect(html).not.toContain("Old description.");
    expect(html).not.toContain("Old twitter description.");
  });

  it("covers every route the shell is served for", () => {
    // A route that reaches the shell without an entry here inherits the
    // homepage canonical again, which is the whole bug. The homepage is the
    // one deliberate exception.
    const samples = [
      "/", "/dashboard", "/scan", "/scan/abc", "/report/abc", "/share/abc",
      "/monitor", "/learn", "/domains", "/settings", "/privacy", "/terms",
      "/sign-in", "/register", "/forgot-password", "/reset-password", "/verify-email",
    ];
    for (const path of samples) {
      expect(SPA_ROUTES.some((re) => re.test(path)), `${path} should be an SPA route`).toBe(true);
      if (path !== "/") {
        expect(metaForPath(path), `${path} has no metadata entry`).not.toBeNull();
      }
    }
  });
});
