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
});
