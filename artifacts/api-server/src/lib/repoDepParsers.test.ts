import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { startOsvStub } from "./osvStub.testkit";
import { osvCache } from "./cveCheckOsv";

// OSV is the only network the dependency check uses. It is a real local server that answers like OSV.dev
// (lib/osvStub.testkit.ts), so the real client's queries, cache and error handling all run; the answers are decided here.
const osv = await startOsvStub();
beforeEach(() => osvCache.clear()); // a verdict cached by an earlier test would otherwise answer for this one
afterAll(() => osv.stop());

import {
  parsePackageLock, parseYarnLock, parsePnpmLock, parseBunLock, parseRequirements, parseTomlPackages, parsePipfileLock, parseGoMod,
  parseGemfileLock, parseComposerLock, parseLockfile, isLockfile, isManifest,
} from "./repoDepParsers";
import { dependencyFindings } from "./repoCheckDeps";

const names = (list: Array<{ name: string; version: string }>) => list.map((p) => `${p.name}@${p.version}`);

describe("npm lockfiles", () => {
  it("reads yarn classic and berry, and skips workspaces and aliases", () => {
    const classic = `# yarn lockfile v1\n\n\n"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n  version "7.12.13"\n  resolved "https://x"\n\nlodash@^4.17.15:\n  version "4.17.20"\n`;
    expect(names(parseYarnLock(classic))).toEqual(["@babel/code-frame@7.12.13", "lodash@4.17.20"]);
    const berry = `__metadata:\n  version: 6\n\n"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n"my-app@workspace:.":\n  version: 0.0.0-use.local\n\n"foo@npm:bar@^1.0.0":\n  version: 1.0.0\n`;
    expect(names(parseYarnLock(berry))).toEqual(["lodash@4.17.21"]);
  });

  it("reads pnpm v9, v6 and v5, from the packages section only", () => {
    const v9 = `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n  '@babel/core@7.24.0':\n    resolution: {integrity: sha512-y}\n  react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-z}\nsnapshots:\n  lodash@4.17.21: {}\n`;
    expect(names(parsePnpmLock(v9))).toEqual(["lodash@4.17.21", "@babel/core@7.24.0", "react-dom@18.2.0"]);
    expect(names(parsePnpmLock(`packages:\n  /lodash@4.17.21:\n    dev: false\n  /@babel/core@7.1.2:\n    dev: true\n`))).toEqual(["lodash@4.17.21", "@babel/core@7.1.2"]);
    const v5 = parsePnpmLock(`packages:\n  /lodash/4.17.21:\n    dev: false\n  /@babel/core/7.1.2:\n    dev: true\n`);
    expect(names(v5)).toEqual(["lodash@4.17.21", "@babel/core@7.1.2"]);
    expect(v5[1]!.dev).toBe(true);
    expect(v5[0]!.dev).toBeUndefined();
  });

  it("reads bun.lock", () => {
    const bun = `{ "lockfileVersion": 1, "packages": { "lodash": ["lodash@4.17.21", "", {}, "sha512-a"], "@types/node": ["@types/node@20.1.0", "", { "dependencies": { "undici-types": "~5" } }, "sha512-b"] } }`;
    expect(names(parseBunLock(bun))).toEqual(["lodash@4.17.21", "@types/node@20.1.0"]);
  });

  it("reads package-lock v3 with dev flags, and v1", () => {
    const v3 = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, "node_modules/lodash": { version: "4.17.21" }, "node_modules/jest": { version: "29.0.0", dev: true }, "node_modules/a/node_modules/b": { version: "1.0.0" } } });
    const got = parsePackageLock(v3);
    expect(names(got)).toEqual(["lodash@4.17.21", "jest@29.0.0", "b@1.0.0"]);
    expect(got[1]!.dev).toBe(true);
    const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { lodash: { version: "4.17.20", dependencies: { inner: { version: "1.2.3" } } } } });
    expect(names(parsePackageLock(v1))).toEqual(["lodash@4.17.20", "inner@1.2.3"]);
    expect(parsePackageLock("not json")).toEqual([]);
  });
});

describe("Python, Go, Rust, Ruby and PHP", () => {
  it("reads only pinned requirements, whatever else is on the line", () => {
    const body = `# base\nDjango==4.2.1\nrequests[security]==2.31.0 ; python_version > "3"\nflask>=2.0\n-r base.txt\nnumpy===1.26.0 \\\n    --hash=sha256:abc\nPillow==10.0.0  # image\n`;
    expect(names(parseRequirements("requirements.txt", body))).toEqual(["django@4.2.1", "requests@2.31.0", "numpy@1.26.0", "pillow@10.0.0"]);
    expect(parseRequirements("requirements-dev.txt", "pytest==7.0.0")[0]!.dev).toBe(true);
    expect(parseRequirements("requirements.txt", "pytest==7.0.0")[0]!.dev).toBeUndefined();
  });

  it("reads poetry.lock and uv.lock, skipping the project's own and git/path packages", () => {
    const poetry = `[[package]]\nname = "Django"\nversion = "4.2.1"\ncategory = "main"\n\n[package.dependencies]\nasgiref = ">=3.6.0,<4"\n\n[[package]]\nname = "pytest"\nversion = "7.0.0"\ncategory = "dev"\n\n[[package]]\nname = "mylocal"\nversion = "0.1.0"\n\n[package.source]\ntype = "directory"\nurl = "../mylocal"\n`;
    const got = parseTomlPackages("PyPI", poetry);
    expect(names(got)).toEqual(["django@4.2.1", "pytest@7.0.0"]);
    expect(got[1]!.dev).toBe(true);
    const uv = `[[package]]\nname = "requests"\nversion = "2.31.0"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\n`;
    expect(names(parseTomlPackages("PyPI", uv))).toEqual(["requests@2.31.0"]);
  });

  it("reads Pipfile.lock", () => {
    const body = JSON.stringify({ default: { Django: { version: "==4.2.1" }, loose: { version: ">=1" } }, develop: { pytest: { version: "==7.0.0" } } });
    const got = parsePipfileLock(body);
    expect(names(got)).toEqual(["django@4.2.1", "pytest@7.0.0"]);
    expect(got[1]!.dev).toBe(true);
  });

  it("reads go.mod, dropping the v and pseudo-versions", () => {
    const body = `module x\ngo 1.21\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/text v0.3.7 // indirect\n\texample.com/pseudo v0.0.0-20200101000000-abcdefabcdef\n)\nrequire github.com/stretchr/testify v1.8.0\n`;
    expect(parseGoMod(body).map((p) => `${p.ecosystem}:${p.name}@${p.version}`)).toEqual(["Go:github.com/gin-gonic/gin@1.9.0", "Go:golang.org/x/text@0.3.7", "Go:github.com/stretchr/testify@1.8.0"]);
  });

  it("reads Cargo.lock (registry crates only), Gemfile.lock and composer.lock", () => {
    const cargo = `[[package]]\nname = "serde"\nversion = "1.0.150"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "myapp"\nversion = "0.1.0"\n`;
    expect(parseTomlPackages("crates.io", cargo).map((p) => `${p.ecosystem}:${p.name}@${p.version}`)).toEqual(["crates.io:serde@1.0.150"]);
    const gem = `GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n    nokogiri (1.13.9-x86_64-linux)\n\nPLATFORMS\n  ruby\n`;
    expect(parseGemfileLock(gem).map((p) => `${p.ecosystem}:${p.name}@${p.version}`)).toEqual(["RubyGems:rails@7.0.4", "RubyGems:nokogiri@1.13.9"]);
    const composer = JSON.stringify({ packages: [{ name: "laravel/framework", version: "v10.1.0" }, { name: "x/dev", version: "dev-main" }], "packages-dev": [{ name: "phpunit/phpunit", version: "10.0.0" }] });
    const got = parseComposerLock(composer);
    expect(got.map((p) => `${p.ecosystem}:${p.name}@${p.version}`)).toEqual(["Packagist:laravel/framework@10.1.0", "Packagist:phpunit/phpunit@10.0.0"]);
    expect(got[1]!.dev).toBe(true);
  });

  it("picks the reader from the file name, and ignores vendored copies", () => {
    expect(names(parseLockfile("backend/poetry.lock", `[[package]]\nname = "a"\nversion = "1.0.0"\n`))).toEqual(["a@1.0.0"]);
    expect(parseLockfile("README.md", "x")).toEqual([]);
    expect(isLockfile("pnpm-lock.yaml")).toBe(true);
    expect(isLockfile("node_modules/x/yarn.lock")).toBe(false);
    expect(isManifest("services/api/requirements-prod.txt")).toBe(true);
    expect(isManifest("vendor/x/go.mod")).toBe(false);
  });
});

const advisory = (id: string, score = "9.8") => ({ id, aliases: [], summary: `Advisory ${id}`, severity: [{ type: "CVSS_V3", score }] });

describe("findings from several ecosystems", () => {
  it("asks OSV in each package's own ecosystem and names the file and repository", async () => {
    osv.asked.length = 0;
    osv.answers = new Map([["PyPI:django@4.2.1", [advisory("GHSA-aaaa")]]]);
    const out = await dependencyFindings(
      [{ path: "api/poetry.lock", content: `[[package]]\nname = "Django"\nversion = "4.2.1"\n` }, { path: "go.mod", content: "require github.com/gin-gonic/gin v1.9.0\n" }],
      { owner: "acme", repo: "app" },
    );
    expect(osv.asked).toEqual(expect.arrayContaining(["PyPI:django@4.2.1", "Go:github.com/gin-gonic/gin@1.9.0"]));
    expect(out.findings).toHaveLength(1);
    const f = out.findings[0]!;
    expect(f.name).toBe("Vulnerable dependency: django 4.2.1");
    expect(f.evidence).toContain("Repository: acme/app");
    expect(f.evidence).toContain("File: api/poetry.lock");
    expect(f.description).toContain("in the repository acme/app");
    expect(f.solution).not.toMatch(/stop serving/i);
  });

  it("reports an OSV malicious-package record as critical, whatever else is known", async () => {
    osv.answers = new Map([["npm:evil-pkg@1.0.0", [{ id: "MAL-2024-1234", summary: "Malicious code in evil-pkg" }, advisory("GHSA-bbbb", "3.1")]]]);
    const out = await dependencyFindings([{ path: "package-lock.json", content: JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/evil-pkg": { version: "1.0.0" } } }) }], { owner: "acme", repo: "app" });
    expect(out.findings[0]).toMatchObject({ name: "Malicious package: evil-pkg 1.0.0", severity: "critical", category: "Supply Chain Security" });
    expect(out.findings[0]!.solution).toMatch(/rotate/i);
  });

  it("rates a vulnerability in a development-only dependency one step lower, and never above medium", async () => {
    osv.answers = new Map([["npm:jest-thing@1.0.0", [advisory("GHSA-cccc")]], ["npm:runtime-thing@1.0.0", [advisory("GHSA-dddd")]]]);
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/jest-thing": { version: "1.0.0", dev: true }, "node_modules/runtime-thing": { version: "1.0.0" } } });
    const out = await dependencyFindings([{ path: "package-lock.json", content: lock }], { owner: "acme", repo: "app" });
    const by = Object.fromEntries(out.findings.map((x) => [x.name, x]));
    expect(by["Vulnerable dependency: runtime-thing 1.0.0"]!.severity).toBe("critical");
    expect(by["Vulnerable dependency: jest-thing 1.0.0"]!.severity).toBe("medium");
    expect(by["Vulnerable dependency: jest-thing 1.0.0"]!.description).toMatch(/development, tests or examples/i);
  });

  it("counts a package as development-only only if every place it appears says so", async () => {
    osv.answers = new Map([["npm:shared@1.0.0", [advisory("GHSA-eeee")]]]);
    const out = await dependencyFindings(
      [
        { path: "a/package.json", content: JSON.stringify({ devDependencies: { shared: "1.0.0" } }) },
        { path: "b/package.json", content: JSON.stringify({ dependencies: { shared: "1.0.0" } }) },
      ],
      { owner: "acme", repo: "app" },
    );
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]!.severity).toBe("critical");
  });

  it("keeps the website wording when there is no repository", async () => {
    osv.answers = new Map([["npm:lodash@4.17.20", [advisory("GHSA-ffff")]]]);
    const out = await dependencyFindings([{ path: "package.json", content: JSON.stringify({ dependencies: { lodash: "4.17.20" } }) }]);
    expect(out.findings[0]!.solution).toMatch(/stop serving/i);
  });
});

describe("counting advisories", () => {
  it("counts an issue once when OSV lists it as both a GitHub advisory and a PYSEC record", async () => {
    osv.answers = new Map([["PyPI:pyjwt@2.10.1", [
      { id: "GHSA-aaaa-1", aliases: ["CVE-2026-1111", "PYSEC-2026-1"], summary: "One", severity: [{ type: "CVSS_V3", score: "7.5" }] },
      { id: "PYSEC-2026-1", aliases: ["CVE-2026-1111", "GHSA-aaaa-1"], summary: "One", severity: [{ type: "CVSS_V3", score: "7.5" }] },
      { id: "GHSA-bbbb-2", aliases: ["CVE-2026-2222"], summary: "Two", severity: [{ type: "CVSS_V3", score: "5.5" }] },
    ]]]);
    const out = await dependencyFindings([{ path: "requirements.txt", content: "PyJWT==2.10.1\n" }], { owner: "acme", repo: "app" });
    expect(out.findings[0]!.description).toContain("has 2 known advisories");
  });
});

describe("sample dependency files", () => {
  it("rates a vulnerability in an examples folder one step lower, like a development dependency", async () => {
    osv.answers = new Map([["PyPI:flask@2.3.2", [advisory("GHSA-flsk")]]]);
    const out = await dependencyFindings([{ path: "examples/celery/requirements.txt", content: "flask==2.3.2\n" }], { owner: "pallets", repo: "flask" });
    expect(out.findings[0]!.severity).toBe("medium");
    const real = await dependencyFindings([{ path: "requirements.txt", content: "flask==2.3.2\n" }], { owner: "pallets", repo: "flask" });
    expect(real.findings[0]!.severity).toBe("critical");
  });
});
