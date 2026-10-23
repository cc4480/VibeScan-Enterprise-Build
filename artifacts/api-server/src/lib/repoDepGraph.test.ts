import { describe, it, expect } from "vitest";
import { markDevOnly, devOnlyNames } from "./repoDepGraph";
import { parseLockfile } from "./repoDepParsers";

const devNames = (path: string, body: string, manifest?: string) =>
  markDevOnly(path, body, parseLockfile(path, body), manifest).filter((p) => p.dev).map((p) => p.name).sort();

describe("devOnlyNames", () => {
  const edges = new Map([["app", ["react"]], ["react", ["scheduler"]], ["vite", ["esbuild", "scheduler"]], ["jest", ["chalk"]]]);

  it("is what only the development roots reach", () => {
    expect([...devOnlyNames({ prod: ["app"], dev: ["vite", "jest"], edges })].sort()).toEqual(["chalk", "esbuild", "jest", "vite"]);
  });

  it("never marks a package that production also reaches (scheduler is used by react and by vite)", () => {
    expect(devOnlyNames({ prod: ["app"], dev: ["vite"], edges }).has("scheduler")).toBe(false);
  });

  it("marks nothing when the graph was not understood (no production roots)", () => {
    expect(devOnlyNames({ prod: [], dev: ["vite"], edges }).size).toBe(0);
  });
});

describe("bun.lock", () => {
  const body = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "app", "dependencies": { "react": "^18.3.1" }, "devDependencies": { "vite": "^5.4.0", },  },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-a"],
    "loose-envify": ["loose-envify@1.4.0", "", {}, "sha512-b"],
    "vite": ["vite@5.4.0", "", { "dependencies": { "esbuild": "^0.21.3", "loose-envify": "^1.1.0" } }, "sha512-c"],
    "esbuild": ["esbuild@0.21.5", "", {}, "sha512-d"],
  },
}`;
  it("reads the workspace's dev and production roots (trailing commas included)", () => {
    expect(devNames("bun.lock", body)).toEqual(["esbuild", "vite"]);
  });
});

describe("pnpm-lock.yaml", () => {
  it("v9: importers give the roots, snapshots give the edges", () => {
    const body = `lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react:\n        specifier: ^18.3.1\n        version: 18.3.1\n    devDependencies:\n      vite:\n        specifier: ^5.4.0\n        version: 5.4.0\n\npackages:\n\n  react@18.3.1:\n    resolution: {integrity: sha512-a}\n\n  vite@5.4.0:\n    resolution: {integrity: sha512-b}\n\n  esbuild@0.21.5:\n    resolution: {integrity: sha512-c}\n\n  loose-envify@1.4.0:\n    resolution: {integrity: sha512-d}\n\nsnapshots:\n\n  react@18.3.1:\n    dependencies:\n      loose-envify: 1.4.0\n\n  vite@5.4.0:\n    dependencies:\n      esbuild: 0.21.5\n      loose-envify: 1.4.0\n\n  esbuild@0.21.5: {}\n\n  loose-envify@1.4.0: {}\n`;
    expect(devNames("pnpm-lock.yaml", body)).toEqual(["esbuild", "vite"]);
  });

  it("v5: the root's direct maps give the roots, packages give the edges", () => {
    const body = `lockfileVersion: 5.4\n\nspecifiers:\n  react: ^18.0.0\n  vite: ^4.0.0\n\ndependencies:\n  react: 18.2.0\n\ndevDependencies:\n  vite: 4.0.0\n\npackages:\n\n  /react/18.2.0:\n    resolution: {integrity: sha512-a}\n    dependencies:\n      loose-envify: 1.4.0\n    dev: false\n\n  /vite/4.0.0:\n    resolution: {integrity: sha512-b}\n    dependencies:\n      esbuild: 0.16.0\n    dev: true\n\n  /esbuild/0.16.0:\n    resolution: {integrity: sha512-c}\n    dev: true\n\n  /loose-envify/1.4.0:\n    resolution: {integrity: sha512-d}\n    dev: false\n`;
    const dev = devNames("pnpm-lock.yaml", body);
    expect(dev).toContain("vite");
    expect(dev).toContain("esbuild");
    expect(dev).not.toContain("react");
    expect(dev).not.toContain("loose-envify");
  });
});

describe("yarn.lock", () => {
  const lock = `# yarn lockfile v1\n\n\nesbuild@^0.21.0:\n  version "0.21.5"\n\nloose-envify@^1.1.0:\n  version "1.4.0"\n\nreact@^18.0.0:\n  version "18.3.1"\n  dependencies:\n    loose-envify "^1.1.0"\n\nvite@^5.0.0:\n  version "5.4.0"\n  dependencies:\n    esbuild "^0.21.0"\n    loose-envify "^1.1.0"\n`;
  const manifest = JSON.stringify({ dependencies: { react: "^18.0.0" }, devDependencies: { vite: "^5.0.0" } });

  it("needs the project's package.json beside it for the roots", () => {
    expect(devNames("yarn.lock", lock, manifest)).toEqual(["esbuild", "vite"]);
  });

  it("marks nothing without that package.json", () => {
    expect(devNames("yarn.lock", lock)).toEqual([]);
  });
});

describe("Python lockfiles", () => {
  it("uv.lock: the project's dev-dependencies are development roots, its dependencies the production ones", () => {
    const body = `[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\ndependencies = [\n    { name = "flask" },\n]\n\n[package.dev-dependencies]\ndev = [\n    { name = "pytest" },\n]\n\n[package.metadata]\nrequires-dist = [{ name = "flask" }]\n\n[[package]]\nname = "flask"\nversion = "3.0.0"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "werkzeug" },\n]\n\n[[package]]\nname = "werkzeug"\nversion = "3.0.1"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "pytest"\nversion = "8.0.0"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "pluggy" },\n]\n\n[[package]]\nname = "pluggy"\nversion = "1.5.0"\nsource = { registry = "https://pypi.org/simple" }\n`;
    expect(devNames("uv.lock", body)).toEqual(["pluggy", "pytest"]);
  });

  it("poetry.lock (v2): a package whose groups do not include main is development-only", () => {
    const body = `[[package]]\nname = "Django"\nversion = "4.2.1"\ngroups = ["main"]\n\n[[package]]\nname = "pytest"\nversion = "7.0.0"\ngroups = ["dev"]\n\n[[package]]\nname = "shared"\nversion = "1.0.0"\ngroups = ["main", "dev"]\n`;
    expect(devNames("poetry.lock", body)).toEqual(["pytest"]);
  });
});

describe("safety: never hides a production package", () => {
  it("leaves everything as it was when the file cannot be read", () => {
    expect(devNames("bun.lock", "{ not json")).toEqual([]);
    expect(devNames("pnpm-lock.yaml", "")).toEqual([]);
    expect(devNames("uv.lock", "garbage")).toEqual([]);
    expect(devNames("Cargo.lock", `[[package]]\nname = "x"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`)).toEqual([]);
  });
});
