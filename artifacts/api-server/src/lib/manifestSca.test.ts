import { describe, it, expect, vi, afterEach } from "vitest";
import { exactVersion, parsePackageJson, scaFromManifest } from "./manifestSca";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("exactVersion", () => {
  it("accepts a pinned version", () => {
    for (const v of ["4.17.20", "1.0.0", "2.3.4-beta.1", "1.2.3+build5"]) {
      expect(exactVersion(v)).toBe(v);
    }
  });

  it("refuses ranges rather than guessing at the floor", () => {
    // The whole point of this module is that it reads versions instead of
    // inferring them. "^4.17.20" does not say what is installed, and asking OSV
    // about 4.17.20 would attribute vulnerabilities the site may not have.
    for (const r of ["^4.17.20", "~1.2.3", ">=2.0.0", "1.x", "*", "latest", "1.2", ""]) {
      expect(exactVersion(r)).toBeNull();
    }
  });

  it("refuses non-registry specs", () => {
    for (const r of [
      "workspace:*",
      "file:../local",
      "git+https://github.com/a/b.git",
      "npm:other@1.2.3",
      "https://example.com/pkg.tgz",
    ]) {
      expect(exactVersion(r)).toBeNull();
    }
  });

  it("refuses anything that is not a string", () => {
    for (const r of [undefined, null, 42, {}, []]) expect(exactVersion(r)).toBeNull();
  });
});

describe("parsePackageJson", () => {
  it("reads pinned dependencies and devDependencies", () => {
    const body = JSON.stringify({
      name: "app",
      dependencies: { lodash: "4.17.20", express: "^4.18.0" },
      devDependencies: { vitest: "1.2.3" },
      peerDependencies: { react: "18.0.0" },
    });
    const pkgs = parsePackageJson(body);
    expect(pkgs).toEqual([
      { name: "lodash", version: "4.17.20" },
      { name: "vitest", version: "1.2.3" },
    ]);
  });

  it("ignores peer and optional deps — neither states what is installed", () => {
    const body = JSON.stringify({
      peerDependencies: { react: "18.0.0" },
      optionalDependencies: { fsevents: "2.3.3" },
    });
    expect(parsePackageJson(body)).toEqual([]);
  });

  it("returns nothing for an SPA shell served at /package.json", () => {
    // A catch-all that answers every path with index.html must produce no
    // packages and therefore no findings — no special-casing needed, JSON.parse
    // simply fails.
    expect(parsePackageJson("<!doctype html><html><body>hi</body></html>")).toEqual([]);
    expect(parsePackageJson("")).toEqual([]);
    expect(parsePackageJson("null")).toEqual([]);
    expect(parsePackageJson("[1,2,3]")).toEqual([]);
  });

  it("caps a very large tree", () => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 500; i++) deps[`pkg-${i}`] = "1.0.0";
    expect(parsePackageJson(JSON.stringify({ dependencies: deps })).length).toBe(60);
  });
});

describe("scaFromManifest", () => {
  const advisory = (id: string, cvss: string, fixed: string, summary?: string) => ({
    id,
    aliases: [id],
    ...(summary ? { summary } : {}),
    severity: [{ type: "CVSS_V3", score: `CVSS:3.1/AV:N/${cvss}` }],
    affected: [{ ranges: [{ events: [{ fixed }] }] }],
  });

  it("emits ONE finding per package, not one per advisory", async () => {
    // Eleven advisories against one dependency describe one action: upgrade it.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          vulns: [
            advisory("CVE-2020-8203", "9.8", "4.17.21", "Prototype pollution"),
            advisory("CVE-2021-23337", "7.2", "4.17.20"),
            advisory("CVE-2020-28500", "5.3", "4.17.19"),
          ],
        }),
      }),
    );
    const out = await scaFromManifest([{ name: "lodash", version: "4.17.15" }], "/package.json");
    expect(out).toHaveLength(1);
    expect(out[0]!.name).toBe("Vulnerable dependency: lodash 4.17.15");
    // Severity tracks the worst advisory.
    expect(out[0]!.severity).toBe("critical");
    // And the fix must clear ALL of them, not just the worst.
    expect(out[0]!.solution).toContain("4.17.21");
    expect(out[0]!.description).toContain("CVE-2020-8203");
  });

  it("says nothing about a package with no advisories", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => ({ vulns: [] }) }));
    expect(await scaFromManifest([{ name: "clean-pkg", version: "1.0.0" }], "/package.json")).toEqual([]);
  });

  it("reports higher confidence than a fingerprint guess, and names the source", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ vulns: [advisory("CVE-2021-1", "7.5", "2.0.0")] }),
      }),
    );
    const [f] = await scaFromManifest([{ name: "pkg", version: "1.0.0" }], "/package.json");
    // version_heuristic sits at 48 because it is inferred. This was read.
    expect(f!.confidence).toBeGreaterThan(80);
    expect(f!.evidence).toContain("/package.json");
    expect(f!.evidence).toContain('"pkg": "1.0.0"');
  });

  it("survives an OSV failure without losing the other packages", async () => {
    let call = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => {
        call += 1;
        if (call === 1) throw new Error("network down");
        return { ok: true, json: async () => ({ vulns: [advisory("CVE-2021-2", "9.1", "3.0.0")] }) };
      }),
    );
    const out = await scaFromManifest(
      [
        { name: "first", version: "1.0.0" },
        { name: "second", version: "1.0.0" },
      ],
      "/package.json",
    );
    // One lookup died; the other still reported.
    expect(out.length).toBeGreaterThanOrEqual(1);
  });

  it("does nothing when there are no packages", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await scaFromManifest([], "/package.json")).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
