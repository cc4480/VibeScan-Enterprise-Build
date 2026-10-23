import { describe, it, expect, beforeEach, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { useHstsPreloadStub } from "./hstsPreloadStub.testkit";
import { runAllProbes, checkHttpsRedirect } from "./probes.js";

/**
 * A check that fails must be reported as not-run, never as clean.
 *
 * This is the defect these tests exist for: every check inside runAllProbes was
 * wrapped so that a rejection became an empty array, and the scan then reported
 * nothing from it. "The check crashed" and "the check ran and your site is fine"
 * produced byte-identical output, at the same grade. Silence has to mean one
 * thing only.
 *
 * The site being scanned is https://example.test/, a name that never resolves, so every request to it really fails. The
 * plain-HTTP address the redirect check requests (HTTP_REDIRECT_PROBE_URL) and the HSTS preload API are real servers on
 * loopback: one is made to drop connections or answer, the other says whether the site is preloaded.
 */

const preload = await useHstsPreloadStub();

/** The site's plain-HTTP side. `dropFirst` connections are cut without an answer; after that it answers `status`. */
const plain = { dropFirst: 0, status: 200, requests: 0 };
const plainServer = http.createServer((req, res) => {
  plain.requests++;
  if (plain.dropFirst > 0) { plain.dropFirst--; req.socket.destroy(); return; }
  res.writeHead(plain.status, { "content-type": "text/html" }).end("<html><body>plain http site</body></html>");
});
await new Promise<void>((r) => plainServer.listen(0, "127.0.0.1", r));
const PLAIN_URL = `http://127.0.0.1:${(plainServer.address() as AddressInfo).port}/`;

// A port nothing listens on: the connection is refused.
const unusedPort = await new Promise<number>((resolve) => {
  const s = http.createServer();
  s.listen(0, "127.0.0.1", () => { const p = (s.address() as AddressInfo).port; s.close(() => resolve(p)); });
});
const DEAD_URL = `http://127.0.0.1:${unusedPort}/`;

afterAll(() => new Promise<void>((r) => {
  delete process.env["HTTP_REDIRECT_PROBE_URL"];
  plainServer.closeAllConnections();
  plainServer.close(() => r());
}));

beforeEach(() => {
  plain.dropFirst = 0;
  plain.status = 200;
  plain.requests = 0;
  process.env["HTTP_REDIRECT_PROBE_URL"] = PLAIN_URL;
});

const SITE = "https://example.test/";

describe("runAllProbes failure reporting", () => {
  it("names the check that threw instead of dropping it", async () => {
    // The plain-HTTP address refuses every connection, so checkHttpsRedirect exhausts its retry and throws.
    process.env["HTTP_REDIRECT_PROBE_URL"] = DEAD_URL;
    const failures: string[] = [];
    await runAllProbes(SITE, "<html></html>", false, (name) => {
      failures.push(name);
    });

    expect(failures).toContain("HTTP to HTTPS redirect");
  });

  it("does not report a failure when the check simply finds nothing", async () => {
    // A reachable plain-HTTP side on a preloaded host: the check answers, finds no problem, and must not appear as
    // "could not be completed".
    preload.statuses.set("example.test", "preloaded");
    const failures: string[] = [];
    await runAllProbes(SITE, "<html></html>", false, (name) => {
      failures.push(name);
    });

    expect(failures).not.toContain("HTTP to HTTPS redirect");
  });

  it("still returns the findings from checks that did succeed", async () => {
    // One failing check must not take the whole family down with it — the
    // surviving checks' findings still have to reach the report.
    process.env["HTTP_REDIRECT_PROBE_URL"] = DEAD_URL;
    const page = `<html><head><script src="https://widgets.vendor.test/loader.js"></script></head><body></body></html>`;
    const failures: string[] = [];
    const findings = await runAllProbes(SITE, page, false, (name) => {
      failures.push(name);
    });

    expect(failures).toContain("HTTP to HTTPS redirect");
    // The page carries a third-party script with no integrity hash, so the page-reading check still reports.
    expect(findings.some((f) => /Subresource Integrity/i.test(f.name))).toBe(true);
  });

  it("works without a callback, for callers that do not pass one", async () => {
    process.env["HTTP_REDIRECT_PROBE_URL"] = DEAD_URL;
    await expect(runAllProbes(SITE, "<html></html>", false)).resolves.toBeInstanceOf(Array);
  });
});

describe("checkHttpsRedirect retry", () => {
  it("retries once before giving up, so one blip does not lose the finding", async () => {
    // First HTTP attempt fails, second succeeds and shows no redirect to HTTPS.
    plain.dropFirst = 1;
    const findings = await checkHttpsRedirect(SITE);

    expect(plain.requests).toBe(2);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.name).toBe("HTTP Traffic Not Redirected to HTTPS");
  });

  it("throws rather than staying silent when both attempts fail", async () => {
    // Fails open on the finding — a network error is not evidence of a missing
    // redirect, so it must not be reported as one — but it is no longer
    // indistinguishable from success either.
    process.env["HTTP_REDIRECT_PROBE_URL"] = DEAD_URL;
    await expect(checkHttpsRedirect(SITE)).rejects.toThrow(/could not reach/i);
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

  it("does not report a script that only the rendered page contains", async () => {
    const findings = await runAllProbes(SITE, rendered, false, undefined, undefined, undefined, shell);
    expect(findings.some((f) => SRI.test(f.name))).toBe(false);
  });

  it("clean twin: still reports a third-party script the site's own HTML carries", async () => {
    const authored = `<html><head>${injected}</head><body></body></html>`;
    const findings = await runAllProbes(SITE, rendered, false, undefined, undefined, undefined, authored);
    expect(findings.some((f) => SRI.test(f.name))).toBe(true);
  });

  it("without a separate as-served page it reads the page it was given, as before", async () => {
    const findings = await runAllProbes(SITE, rendered, false);
    expect(findings.some((f) => SRI.test(f.name))).toBe(true);
  });
});
