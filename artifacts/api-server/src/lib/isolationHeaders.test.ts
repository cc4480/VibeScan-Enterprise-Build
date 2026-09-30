import { describe, it, expect } from "vitest";
import { checkIsolationHeaders } from "./isolationHeaders";
import { controlsForFinding } from "./compliance";

const URL_ = "https://example.test/";

describe("checkIsolationHeaders", () => {
  it("reports nothing when all three headers are present, whatever their case or value", () => {
    const f = checkIsolationHeaders(
      {
        "Cross-Origin-Opener-Policy": "same-origin",
        "cross-origin-embedder-policy": "credentialless",
        "CROSS-ORIGIN-RESOURCE-POLICY": "same-site",
      },
      URL_,
    );
    expect(f).toEqual([]);
  });

  it("reports each missing header as INFO in Browser Feature Control, tagged CWE-16", () => {
    const f = checkIsolationHeaders({}, URL_);
    expect(f.map((v) => v.name)).toEqual([
      "Missing Cross-Origin-Opener-Policy (COOP)",
      "Missing Cross-Origin-Embedder-Policy (COEP)",
      "Missing Cross-Origin-Resource-Policy (CORP)",
    ]);
    for (const v of f) {
      expect(v.severity).toBe("info");
      expect(v.category).toBe("Browser Feature Control");
      expect(v.cweId).toBe("CWE-16");
      expect(v.evidence).toContain(URL_);
    }
  });

  it("only flags the header that is actually absent", () => {
    const f = checkIsolationHeaders(
      { "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin" },
      URL_,
    );
    expect(f.map((v) => v.name)).toEqual(["Missing Cross-Origin-Embedder-Policy (COEP)"]);
  });

  it("does not present a missing isolation header as evidence about origin validation (ASVS V14.5.3)", () => {
    for (const v of checkIsolationHeaders({}, URL_)) {
      const controls = controlsForFinding({ cweId: v.cweId, category: v.category });
      expect(controls.map((c) => c.control)).not.toContain("V14.5.3");
    }
  });
});
