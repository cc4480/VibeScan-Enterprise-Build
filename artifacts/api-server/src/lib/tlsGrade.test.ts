/**
 * A TLS grade must come from an SSL Labs assessment that completed. The basic
 * scan measures nothing about TLS, so any grade it assigns is invented and would
 * be reported when SSL Labs times out or errors (checkSslLabs then returns null).
 */
import { describe, it, expect } from "vitest";
import { moduleSource } from "../testing/moduleSource";
import { join } from "node:path";

const src = (f: string) => moduleSource(__dirname, f);

describe("TLS grade is never fabricated", () => {
  it("the header scan assigns no letter grade of its own", () => {
    expect(src("scanner.ts")).not.toMatch(/tlsGrade\s*(?::[^=]+)?=[^;]*["'][A-F][+-]?["']/);
  });

  it("the worker copies a grade only from a completed SSL Labs result", () => {
    const w = src("worker.ts");
    expect(w).toMatch(/if \(sslLabsResult\) \{[\s\S]*?scanResult\.tlsGrade = sslLabsResult\.grade/);
    expect(w).not.toMatch(/tlsGrade\s*=\s*["']/);
  });

  it("the scanner's own TLS configuration check sets no grade and claims no SSL Labs result", () => {
    const t = src("tlsCheck.ts");
    expect(t).not.toMatch(/tlsGrade/);
    // It may name SSL Labs in its comments (what it replaces), but never builds a finding or record from it.
    expect(t.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "")).not.toMatch(/ssl labs|ssllabs/i);
    // And the worker never feeds the new check's output into the grade.
    expect(src("workerSideChecks.ts")).not.toMatch(/tlsGrade\s*=\s*[^;]*tlsCheck|tlsGrade\s*=\s*[^;]*inspection/);
  });
});
