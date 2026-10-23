import { describe, it, expect } from "vitest";
import { compromisedScriptFindings, isCompromisedScriptHost } from "./compromisedScriptHosts";

const page = (scripts: string) => `<html><head>${scripts}</head><body></body></html>`;
const base = "https://shop.example.com/";

describe("a script from a host tied to the Polyfill.io attack", () => {
  it("is High when the page loads polyfill.io, or a subdomain of a listed domain", () => {
    const f = compromisedScriptFindings(page(`<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>`), base);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", cweId: "CWE-829" });
    expect(compromisedScriptFindings(page(`<script src="//cdn.bootcdn.net/ajax/libs/jquery.min.js"></script>`), base)).toHaveLength(1);
  });

  it("lists every compromised script once, in one finding", () => {
    const f = compromisedScriptFindings(page(`<script src="https://polyfill.io/a.js"></script><script src="https://polyfill.io/a.js"></script><script src="https://staticfile.org/b.js"></script>`), base);
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toContain("https://polyfill.io/a.js");
    expect(f[0]!.evidence).toContain("https://staticfile.org/b.js");
  });

  it("clean twin: a lookalike domain, a suffix trick, a trusted CDN and a relative script are not reported", () => {
    expect(compromisedScriptFindings(page(`<script src="https://evil-polyfill.io/x.js"></script>`), base)).toEqual([]);
    expect(compromisedScriptFindings(page(`<script src="https://polyfill.io.attacker.test/x.js"></script>`), base)).toEqual([]);
    expect(compromisedScriptFindings(page(`<script src="https://cdn.jsdelivr.net/npm/x.js"></script>`), base)).toEqual([]);
    expect(compromisedScriptFindings(page(`<script src="/assets/app.js"></script>`), base)).toEqual([]);
  });

  it("matches the host alone, case-insensitively and with a trailing dot", () => {
    expect(isCompromisedScriptHost("CDN.POLYFILL.IO")).toBe(true);
    expect(isCompromisedScriptHost("polyfill.io.")).toBe(true);
    expect(isCompromisedScriptHost("example.com")).toBe(false);
  });
});
