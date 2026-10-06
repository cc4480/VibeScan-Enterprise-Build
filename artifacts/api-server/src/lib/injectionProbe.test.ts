import { describe, it, expect, vi, afterEach } from "vitest";
import { runInjectionProbes } from "./injectionProbe.js";

// Mocking fetch: use vi.stubGlobal (see ENGINEERING.md) — vi.spyOn(globalThis,"fetch")
// does not apply because the module closed over globalThis.fetch at import time.
afterEach(() => vi.unstubAllGlobals());

/** Build a fetch mock that turns each request into a body via `render(value)`. */
function mockFetch(render: (value: string, endsWithQuote: boolean) => string, contentType = "text/html; charset=utf-8") {
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
    const u = new URL(String(input));
    const value = [...u.searchParams.values()][0] ?? "";
    const body = render(value, value.endsWith("'"));
    return { status: 200, text: async () => body, headers: new Headers({ "content-type": contentType }) } as unknown as Response;
  }));
}

const TARGET = "https://example.com/search";

describe("runInjectionProbes — reflected XSS", () => {
  it("flags XSS when the injected markers reflect unencoded", async () => {
    // App echoes the raw parameter value into the HTML — vulnerable.
    mockFetch((value) => `<html><body>Results for: ${value}</body></html>`);
    const findings = await runInjectionProbes(`${TARGET}?q=test`, "");
    const xss = findings.find((f) => f.name === "Reflected Cross-Site Scripting (XSS)");
    expect(xss).toBeDefined();
    expect(xss!.severity).toBe("high");
    expect(xss!.cweId).toBe("CWE-79");
  });

  it("does NOT flag XSS when the app HTML-encodes the reflection", async () => {
    // Safe app: angle brackets are encoded, so the "<token>" never appears raw.
    const encode = (s: string) => s.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    mockFetch((value) => `<html><body>Results for: ${encode(value)}</body></html>`);
    const findings = await runInjectionProbes(`${TARGET}?q=test`, "");
    expect(findings.find((f) => f.name === "Reflected Cross-Site Scripting (XSS)")).toBeUndefined();
  });
});

describe("runInjectionProbes — reflected XSS needs a response a browser renders as HTML", () => {
  const reflect = (value: string) => `{"echo":"${value}"}`;
  it("does NOT flag a JSON API that echoes the input back with the angle brackets intact", async () => {
    mockFetch(reflect, "application/json");
    const findings = await runInjectionProbes(`${TARGET}?q=test`, "");
    expect(findings.find((f) => f.name === "Reflected Cross-Site Scripting (XSS)")).toBeUndefined();
  });
  it("does NOT flag plain text either", async () => {
    mockFetch((v) => v, "text/plain");
    expect((await runInjectionProbes(`${TARGET}?q=test`, "")).find((f) => f.name.includes("Cross-Site"))).toBeUndefined();
  });
  it("still flags the same echo when it is served as HTML", async () => {
    mockFetch(reflect, "text/html");
    expect((await runInjectionProbes(`${TARGET}?q=test`, "")).find((f) => f.name.includes("Cross-Site"))).toBeDefined();
  });
});

describe("runInjectionProbes — error-based SQLi", () => {
  it("flags SQLi when a quote triggers a DB error absent from the baseline", async () => {
    mockFetch((_value, endsWithQuote) =>
      endsWithQuote
        ? "<html>Warning: You have an error in your SQL syntax near ''' at line 1</html>"
        : "<html>No results</html>", // baseline: clean, and not reflected → no XSS
    );
    const findings = await runInjectionProbes(`${TARGET}?id=1`, "");
    const sqli = findings.find((f) => f.name === "SQL Injection (Error-Based)");
    expect(sqli).toBeDefined();
    expect(sqli!.severity).toBe("critical");
    expect(sqli!.cweId).toBe("CWE-89");
    // The clean/non-reflecting body must not also trip XSS.
    expect(findings.find((f) => f.name === "Reflected Cross-Site Scripting (XSS)")).toBeUndefined();
  });

  it("does NOT flag SQLi when the error signature is present in the baseline too", async () => {
    // A page that always contains a SQL-error-looking string must not false-positive.
    mockFetch(() => "<html>You have an error in your SQL syntax (static help text)</html>");
    const findings = await runInjectionProbes(`${TARGET}?id=1`, "");
    expect(findings.find((f) => f.name === "SQL Injection (Error-Based)")).toBeUndefined();
  });

  it("does NOT flag SQLi on an ordinary page with no DB errors", async () => {
    mockFetch((value) => `<html>You searched for ${value}. Nothing found.</html>`);
    const findings = await runInjectionProbes(`${TARGET}?id=1`, "");
    expect(findings.find((f) => f.name === "SQL Injection (Error-Based)")).toBeUndefined();
  });
});

describe("runInjectionProbes — edge cases", () => {
  it("returns [] for an unparseable target URL", async () => {
    mockFetch(() => "<html></html>");
    expect(await runInjectionProbes("not-a-valid-url", "")).toEqual([]);
  });

  it("returns [] gracefully when every request fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));
    expect(await runInjectionProbes(`${TARGET}?q=1`, "")).toEqual([]);
  });
});

describe("runInjectionProbes — reflection context decides exploitability", () => {
  const xssOf = async () =>
    (await runInjectionProbes(TARGET, "<html></html>")).find((f) => f.name === "Reflected Cross-Site Scripting (XSS)");

  const raw = (v: string) => v; // a page that echoes the value with no encoding at all
  /** Echo the value inside `wrap`, without any encoding, on every request. */
  const echoIn = (wrap: (v: string) => string) => mockFetch((v) => `<html><body>${wrap(raw(v))}</body></html>`);

  it("flags a marker reflected into HTML body text", async () => {
    echoIn((v) => `<p>Results for ${v}</p>`);
    expect(await xssOf()).toBeDefined();
  });

  it("flags a marker that breaks out of an unescaped attribute quote", async () => {
    echoIn((v) => `<input name="q" value="${v}">`);
    expect(await xssOf()).toBeDefined();
  });

  it.each([
    ["a script JSON state block", (v: string) => `<script>window.__S__=${JSON.stringify({ q: v })};</script>`],
    ["an application/json script", (v: string) => `<script type="application/json">${JSON.stringify({ q: v })}</script>`],
    ["an HTML comment", (v: string) => `<!-- q=${v} -->`],
    ["a textarea", (v: string) => `<textarea name="q">${v}</textarea>`],
    ["a title", (v: string) => `<title>${v}</title>`],
    ["a style block", (v: string) => `<style>/* ${v} */</style>`],
    ["a quoted attribute whose quotes are encoded", (v: string) => `<input value="${v.replace(/"/g, "&quot;").replace(/'/g, "&#39;")}">`],
  ])("does not flag a marker inert inside %s", async (_n, wrap) => {
    // The page passes "<" through but neutralises closing sequences, so nothing can break out.
    mockFetch((v) => `<html><body>${wrap(v.replace(/<\//g, "<\\/").replace(/-->/g, "--&gt;"))}</body></html>`);
    expect(await xssOf()).toBeUndefined();
  });

  it.each([
    ["a script block", (v: string) => `<script>var q = "${v}";</script>`],
    ["a textarea", (v: string) => `<textarea>${v}</textarea>`],
    ["a title", (v: string) => `<title>${v}</title>`],
    ["an HTML comment", (v: string) => `<!-- ${v} -->`],
  ])("still flags %s when the closing sequence reflects unencoded (real break-out)", async (_n, wrap) => {
    echoIn(wrap);
    const xss = await xssOf();
    expect(xss).toBeDefined();
    expect(xss!.evidence).toMatch(/break/i);
  });

  it("does not flag a script block that escapes < as \\u003c", async () => {
    echoIn((v) => `<script>var q = "${v.replace(/</g, "\\u003c")}";</script>`);
    expect(await xssOf()).toBeUndefined();
  });
});
