/**
 * The CLI that the GitHub Action wraps (deploy/cli/secscan.mjs). It lives outside
 * the workspace so it can be published on its own; its tests live here.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
// @ts-ignore -- a plain ESM script with no declaration file
import { parseArgs, countAtOrAbove, policyFailure, formatSummary, run, EXIT } from "../../../../deploy/cli/secscan.mjs";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete process.env["SECSCAN_TOKEN"];
});

const TOKEN = ["--token", "ssk_x"];

describe("parseArgs", () => {
  it("takes the URL and defaults sensibly", () => {
    const { opts, error } = parseArgs(["scan", "https://a.example", ...TOKEN]);
    expect(error).toBeUndefined();
    expect(opts).toMatchObject({ url: "https://a.example", failOn: "high", minGrade: null, timeout: 300, token: "ssk_x" });
  });

  it("reads the token from the environment, so it need not appear in a command line", () => {
    process.env["SECSCAN_TOKEN"] = "ssk_env";
    expect(parseArgs(["scan", "https://a.example"]).opts.token).toBe("ssk_env");
  });

  it("refuses without a token, naming where to get one", () => {
    expect(parseArgs(["scan", "https://a.example"]).error).toMatch(/No token/);
  });

  it.each([
    [["scan"], /Give the URL/],
    [["nope", "https://a.example", ...TOKEN], /Usage/],
    [["scan", "https://a.example", "--bogus", ...TOKEN], /Unknown option --bogus/],
    [["scan", "https://a.example", "--fail-on", "urgent", ...TOKEN], /--fail-on/],
    [["scan", "https://a.example", "--min-grade", "Z", ...TOKEN], /--min-grade/],
    [["scan", "https://a.example", "--timeout", "3", ...TOKEN], /--timeout/],
    [["scan", "https://a.example", "--sarif"], /needs a value/],
  ])("rejects bad input %#", (argv, message) => {
    expect(parseArgs(argv).error).toMatch(message);
  });

  it("accepts help without a URL or a token", () => {
    expect(parseArgs(["--help"]).opts.help).toBe(true);
  });
});

describe("policy", () => {
  const findings = { critical: 0, high: 2, medium: 1, low: 0, info: 4, total: 7 };

  it("counts findings at or above a severity", () => {
    expect(countAtOrAbove(findings, "critical")).toBe(0);
    expect(countAtOrAbove(findings, "high")).toBe(2);
    expect(countAtOrAbove(findings, "medium")).toBe(3);
    expect(countAtOrAbove(findings, "info")).toBe(7);
    expect(countAtOrAbove(findings, "none")).toBe(0);
    expect(countAtOrAbove(undefined, "high")).toBe(0);
  });

  it("fails on findings at the chosen level and passes below it", () => {
    expect(policyFailure({ findings }, { failOn: "high", minGrade: null })).toMatch(/2 findings at high or worse/);
    expect(policyFailure({ findings }, { failOn: "critical", minGrade: null })).toBeNull();
    expect(policyFailure({ findings }, { failOn: "none", minGrade: null })).toBeNull();
  });

  it("fails on a grade worse than the minimum", () => {
    expect(policyFailure({ grade: "D", findings: {} }, { failOn: "none", minGrade: "C" })).toMatch(/grade D is worse than C/);
    expect(policyFailure({ grade: "C", findings: {} }, { failOn: "none", minGrade: "C" })).toBeNull();
    expect(policyFailure({ grade: "A", findings: {} }, { failOn: "none", minGrade: "C" })).toBeNull();
  });

  it("does not fail a minimum-grade rule on a scan that has no grade (a bot-protection page), it is reported instead", () => {
    expect(policyFailure({ grade: "N/A", findings: {} }, { failOn: "none", minGrade: "C" })).toBeNull();
    expect(policyFailure({ findings: {} }, { failOn: "none", minGrade: "C" })).toBeNull();
  });
});

describe("formatSummary", () => {
  const scan = { url: "https://a.example", grade: "B", riskScore: 21, findings: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 }, coverage: { ran: 25, skipped: 16, failed: 0, total: 41 }, links: { web: "https://secscan.us/report/r1" } };

  it("says plainly that skipped tests were not checked", () => {
    const text = formatSummary(scan);
    expect(text).toContain("25 ran, 16 skipped, 0 failed");
    expect(text).toContain("skipped tests were NOT checked");
  });

  it("does not print that note when nothing was skipped", () => {
    expect(formatSummary({ ...scan, coverage: { ran: 41, skipped: 0, failed: 0, total: 41 } })).not.toContain("NOT checked");
  });
});

describe("run: exit codes", () => {
  function api(routes: Record<string, () => { status?: number; body: unknown }>) {
    vi.stubGlobal("fetch", async (url: string, init?: { method?: string }) => {
      const path = new URL(url).pathname.replace("/api/v1", "");
      const key = `${init?.method ?? "GET"} ${path}`;
      const handler = routes[key] ?? routes[`* ${path.split("/").slice(0, 3).join("/")}`];
      if (!handler) throw new Error(`no handler for ${key}`);
      const r = handler();
      const text = typeof r.body === "string" ? r.body : JSON.stringify(r.body);
      return { ok: (r.status ?? 200) < 400, status: r.status ?? 200, text: async () => text };
    });
  }
  const done = (over = {}) => ({ id: "s1", url: "https://a.example", status: "complete", grade: "B", findings: { critical: 0, high: 0, medium: 0, low: 0, info: 1, total: 1 }, coverage: { ran: 5, skipped: 0, failed: 0, total: 5 }, ...over });
  const out = () => ({ log: vi.fn(), err: vi.fn(), write: vi.fn() });

  it("0 when the scan finishes and passes", async () => {
    api({ "POST /scans": () => ({ status: 202, body: { id: "s1" } }), "GET /scans/s1": () => ({ body: done() }) });
    const io = out();
    expect(await run(["scan", "https://a.example", ...TOKEN], io)).toBe(EXIT.ok);
    expect(io.log).toHaveBeenCalledWith("PASS");
  });

  it("1 when a finding is at the chosen level", async () => {
    api({ "POST /scans": () => ({ status: 202, body: { id: "s1" } }), "GET /scans/s1": () => ({ body: done({ findings: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 } }) }) });
    const io = out();
    expect(await run(["scan", "https://a.example", ...TOKEN], io)).toBe(EXIT.policy);
    expect(io.err).toHaveBeenCalledWith(expect.stringContaining("FAIL: 1 finding at high or worse"));
  });

  it("writes SARIF and JSON files when asked", async () => {
    api({
      "POST /scans": () => ({ status: 202, body: { id: "s1" } }),
      "GET /scans/s1": () => ({ body: done() }),
      "GET /scans/s1/sarif": () => ({ body: { version: "2.1.0" } }),
      "GET /scans/s1/report": () => ({ body: { report: {} } }),
    });
    const io = out();
    await run(["scan", "https://a.example", ...TOKEN, "--sarif", "o.sarif", "--json", "o.json"], io);
    expect(io.write).toHaveBeenCalledWith("o.sarif", expect.stringContaining("2.1.0"));
    expect(io.write).toHaveBeenCalledWith("o.json", expect.any(String));
  });

  it("2 when the scan itself fails", async () => {
    api({ "POST /scans": () => ({ status: 202, body: { id: "s1" } }), "GET /scans/s1": () => ({ body: done({ status: "failed", error: "Failed to reach target URL" }) }) });
    const io = out();
    expect(await run(["scan", "https://a.example", ...TOKEN], io)).toBe(EXIT.scan);
    expect(io.err).toHaveBeenCalledWith(expect.stringContaining("Failed to reach target URL"));
  });

  it("2 on timeout, and says the scan keeps running", async () => {
    api({ "POST /scans": () => ({ status: 202, body: { id: "s1" } }), "GET /scans/s1": () => ({ body: done({ status: "scanning" }) }) });
    let now = 0;
    vi.spyOn(Date, "now").mockImplementation(() => (now += 100_000));
    const io = out();
    expect(await run(["scan", "https://a.example", ...TOKEN, "--timeout", "10"], io)).toBe(EXIT.scan);
    expect(io.err).toHaveBeenCalledWith(expect.stringContaining("keeps running"));
  });

  it("3 when the token is refused", async () => {
    api({ "POST /scans": () => ({ status: 401, body: { error: { code: "unauthorized", message: "Missing or invalid API token." } } }) });
    const io = out();
    expect(await run(["scan", "https://a.example", ...TOKEN], io)).toBe(EXIT.api);
    expect(io.err).toHaveBeenCalledWith(expect.stringContaining("Token refused"));
  });

  it("3 when the API cannot be reached", async () => {
    vi.stubGlobal("fetch", async () => { throw new Error("getaddrinfo ENOTFOUND"); });
    const io = out();
    expect(await run(["scan", "https://a.example", ...TOKEN], io)).toBe(EXIT.api);
  });

  it("2 for the website's own refusal, such as no scans left", async () => {
    api({ "POST /scans": () => ({ status: 402, body: { error: { code: "payment_required", message: "No scans left" } } }) });
    expect(await run(["scan", "https://a.example", ...TOKEN], out())).toBe(EXIT.scan);
  });

  it("2 for bad usage, before any request is made", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await run(["scan"], out())).toBe(EXIT.scan);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
