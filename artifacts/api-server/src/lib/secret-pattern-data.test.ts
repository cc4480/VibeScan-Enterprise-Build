import { describe, it, expect } from "vitest";
import { SECRET_PATTERNS } from "./secret-pattern-data.js";

describe("SECRET_PATTERNS — Google API key is public-by-design", () => {
  const google = SECRET_PATTERNS.find((p) => /Google API Key/i.test(p.name));

  it("still matches an AIza… key", () => {
    expect(google).toBeDefined();
    expect(google!.pattern.test("AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8")).toBe(true);
  });

  it("reports it as info, not high — the key is browser-facing by design", () => {
    // youtube.com shipped a valid, referrer-restricted AIza key in its embed;
    // the old High "exposed secret" turned that into a false breach headline.
    expect(google!.severity).toBe("info");
  });

  it("still ignores obvious placeholders", () => {
    expect(google!.validate!("AIzaEXAMPLE_KEY_1234567890123456789012")).toBe(false);
  });
});
