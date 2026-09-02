import { describe, it, expect, vi, afterEach } from "vitest";
import { runInjectionProbes } from "./injectionProbe.js";

// Mocking fetch: use vi.stubGlobal (see replit.md) — vi.spyOn(globalThis,"fetch")
// does not apply because the module closed over globalThis.fetch at import time.
afterEach(() => vi.unstubAllGlobals());

/** Build a fetch mock that turns each request into a body via `render(value)`. */
function mockFetch(render: (value: string, endsWithQuote: boolean) => string) {
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
    const u = new URL(String(input));
    const value = [...u.searchParams.values()][0] ?? "";
    const body = render(value, value.endsWith("'"));
    return { status: 200, text: async () => body } as unknown as Response;
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
