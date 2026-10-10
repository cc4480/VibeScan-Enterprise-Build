import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * A check that fails must be reported as not-run, never as clean.
 *
 * This is the defect these tests exist for: every check inside runAllProbes was
 * wrapped so that a rejection became an empty array, and the scan then reported
 * nothing from it. "The check crashed" and "the check ran and your site is fine"
 * produced byte-identical output, at the same grade. Silence has to mean one
 * thing only.
 */

const scanFetchMock = vi.fn();

vi.mock("./http", () => ({
  scanFetch: (...args: unknown[]) => scanFetchMock(...args),
}));

vi.mock("./spaCatchAll", () => ({
  detectCatchAll: async () => null,
  matchesCatchAll: () => false,
}));

beforeEach(() => {
  scanFetchMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function load() {
  return import("./probes.js");
}

describe("runAllProbes failure reporting", () => {
  it("names the check that threw instead of dropping it", async () => {
    // Every fetch rejects, so checkHttpsRedirect exhausts its retry and throws.
    scanFetchMock.mockRejectedValue(new Error("connection reset"));

    const { runAllProbes } = await load();
    const failures: string[] = [];
    await runAllProbes("https://example.test/", "<html></html>", false, (name) => {
      failures.push(name);
    });

    expect(failures).toContain("HTTP to HTTPS redirect");
  });

  it("does not report a failure when the check simply finds nothing", async () => {
    // A reachable target that redirects properly: the check answers, finds no
    // problem, and must not appear as "could not be completed".
    scanFetchMock.mockResolvedValue({
      status: 200,
      body: "",
      headers: {},
      setCookies: [],
      finalUrl: "https://example.test/",
      redirected: true,
    });

    const { runAllProbes } = await load();
    const failures: string[] = [];
    await runAllProbes("https://example.test/", "<html></html>", false, (name) => {
      failures.push(name);
    });

    expect(failures).not.toContain("HTTP to HTTPS redirect");
  });

  it("still returns the findings from checks that did succeed", async () => {
    // One failing check must not take the whole family down with it — the
    // surviving checks' findings still have to reach the report.
    scanFetchMock.mockImplementation((url: string) => {
      if (url.startsWith("http://")) return Promise.reject(new Error("nope"));
      return Promise.resolve({
        status: 200,
        body: "",
        headers: {},
        setCookies: [],
        finalUrl: url,
        redirected: false,
      });
    });

    const { runAllProbes } = await load();
    const failures: string[] = [];
    const findings = await runAllProbes("https://example.test/", "<html></html>", false, (name) => {
      failures.push(name);
    });

    expect(failures).toContain("HTTP to HTTPS redirect");
    // security.txt answered 200 without RFC 9116 fields, so it reports.
    expect(findings.some((f) => /security\.txt/i.test(f.name))).toBe(true);
  });

  it("works without a callback, for callers that do not pass one", async () => {
    scanFetchMock.mockRejectedValue(new Error("connection reset"));
    const { runAllProbes } = await load();
    await expect(
      runAllProbes("https://example.test/", "<html></html>", false),
    ).resolves.toBeInstanceOf(Array);
  });
});

describe("checkHttpsRedirect retry", () => {
  it("retries once before giving up, so one blip does not lose the finding", async () => {
    // First HTTP attempt fails, second succeeds and shows no redirect to HTTPS.
    let httpAttempts = 0;
    scanFetchMock.mockImplementation((url: string) => {
      if (url.startsWith("http://")) {
        httpAttempts++;
        if (httpAttempts === 1) return Promise.resolve(null);
        return Promise.resolve({
          status: 200,
          body: "",
          headers: {},
          setCookies: [],
          finalUrl: "http://example.test/",
          redirected: false,
        });
      }
      // The HSTS preload lookup — answer "not preloaded".
      return Promise.resolve({
        status: 200,
        body: '{"status":"unknown"}',
        headers: {},
        setCookies: [],
        finalUrl: url,
        redirected: false,
      });
    });

    const { checkHttpsRedirect } = await load();
    const findings = await checkHttpsRedirect("https://example.test/");

    expect(httpAttempts).toBe(2);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toBe("HTTP Traffic Not Redirected to HTTPS");
  });

  it("throws rather than staying silent when both attempts fail", async () => {
    // Fails open on the finding — a network error is not evidence of a missing
    // redirect, so it must not be reported as one — but it is no longer
    // indistinguishable from success either.
    scanFetchMock.mockResolvedValue(null);
    const { checkHttpsRedirect } = await load();
    await expect(checkHttpsRedirect("https://example.test/")).rejects.toThrow(/could not reach/i);
  });
});

describe("runAllProbes reads subresource integrity from the page as the server sent it", () => {
  // Found on the first sweep that rendered pages in the headless browser (2026-10-05): dashboard.render.com,
  // app.netlify.com, app.zenhub.com and others gained "External Resources Missing SRI" listing scripts
  // such as cdn.segment.com/next-integrations/..., js.hs-analytics.net/analytics/<timestamp>/...js and a
  // doubleclick URL with random=<timestamp>. Tag loaders inject those at run time. The owner did not write
  // them, cannot pin a hash on a URL that changes per request, and never sees them in their own HTML.
  const SRI = /Subresource Integrity/i;
  const injected = `<script src="https://widgets.vendor.test/loader.js"></script>`;
  const shell = `<html><head><script src="/assets/app.js"></script></head><body><div id="root"></div></body></html>`;
  const rendered = `<html><head><script src="/assets/app.js"></script>${injected}</head><body><div id="root"><h1>App</h1></div></body></html>`;

  beforeEach(() => {
    scanFetchMock.mockRejectedValue(new Error("offline"));
  });

  it("does not report a script that only the rendered page contains", async () => {
    const { runAllProbes } = await load();
    const findings = await runAllProbes("https://example.test/", rendered, false, undefined, undefined, undefined, shell);
    expect(findings.some((f) => SRI.test(f.name))).toBe(false);
  });

  it("clean twin: still reports a third-party script the site's own HTML carries", async () => {
    const { runAllProbes } = await load();
    const authored = `<html><head>${injected}</head><body></body></html>`;
    const findings = await runAllProbes("https://example.test/", rendered, false, undefined, undefined, undefined, authored);
    expect(findings.some((f) => SRI.test(f.name))).toBe(true);
  });

  it("without a separate as-served page it reads the page it was given, as before", async () => {
    const { runAllProbes } = await load();
    const findings = await runAllProbes("https://example.test/", rendered, false);
    expect(findings.some((f) => SRI.test(f.name))).toBe(true);
  });
});
