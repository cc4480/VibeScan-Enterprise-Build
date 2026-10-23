import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
// Imported through the package, not by relative path: this lives in
// @workspace/db but runs here, because that package has no test runner of
// its own and a test nothing executes is worse than no test.
import { resolveMigrationsDir, migrationsDirCandidates, MIGRATION_ADVISORY_LOCK_KEY } from "@workspace/db";

/**
 * Path resolution is the part of this that typechecks perfectly and then fails
 * at runtime, so it is pinned here.
 *
 * In production this module does not exist as a file — esbuild bundles it into
 * artifacts/api-server/dist/index.mjs, where `import.meta.url` points at the
 * bundle and the source-relative "../migrations" is a directory that never
 * existed. The Dockerfile puts the migrations at /app/lib/db/migrations and
 * WORKDIR is /app, so the cwd-relative candidate is the one that must win.
 */

let tmp: string;
let cwd: string;
let savedEnv: string | undefined;

function makeMigrations(dir: string) {
  fs.mkdirSync(path.join(dir, "meta"), { recursive: true });
  fs.writeFileSync(path.join(dir, "meta", "_journal.json"), JSON.stringify({ version: "7", entries: [] }));
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bootmigrate-"));
  cwd = process.cwd();
  savedEnv = process.env["MIGRATIONS_DIR"];
  delete process.env["MIGRATIONS_DIR"];
});

afterEach(() => {
  process.chdir(cwd);
  if (savedEnv === undefined) delete process.env["MIGRATIONS_DIR"];
  else process.env["MIGRATIONS_DIR"] = savedEnv;
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("resolveMigrationsDir", () => {
  it("finds lib/db/migrations relative to the working directory (the container layout)", () => {
    const target = path.join(tmp, "lib", "db", "migrations");
    makeMigrations(target);
    process.chdir(tmp);
    expect(fs.realpathSync(resolveMigrationsDir())).toBe(fs.realpathSync(target));
  });

  it("finds ./migrations when run from inside the db package (the CLI on a laptop)", () => {
    const target = path.join(tmp, "migrations");
    makeMigrations(target);
    process.chdir(tmp);
    expect(fs.realpathSync(resolveMigrationsDir())).toBe(fs.realpathSync(target));
  });

  it("lets MIGRATIONS_DIR override everything", () => {
    const target = path.join(tmp, "somewhere-else");
    makeMigrations(target);
    makeMigrations(path.join(tmp, "lib", "db", "migrations"));
    process.chdir(tmp);
    process.env["MIGRATIONS_DIR"] = target;
    expect(fs.realpathSync(resolveMigrationsDir())).toBe(fs.realpathSync(target));
  });

  // The failure this guards against is the quiet one: a bad COPY leaves an
  // empty migrations/ directory, the migrator finds "no migrations pending",
  // and the service boots happily against a database it never migrated —
  // which is precisely what this whole change exists to prevent.
  //
  // Candidates are passed explicitly here. Running from source, the last
  // fallback resolves to the repository's REAL migrations folder, so a
  // "nothing found" state cannot be produced by juggling the cwd — the test
  // would be asserting against a directory that legitimately exists.
  it("skips a directory that has no journal rather than accepting it as empty-but-valid", () => {
    const empty = path.join(tmp, "empty");
    const real = path.join(tmp, "real");
    fs.mkdirSync(empty, { recursive: true });
    makeMigrations(real);
    expect(fs.realpathSync(resolveMigrationsDir([empty, real]))).toBe(fs.realpathSync(real));
  });

  it("throws, naming every path it tried, when none of them hold migrations", () => {
    const a = path.join(tmp, "nope-a");
    const b = path.join(tmp, "nope-b");
    expect(() => resolveMigrationsDir([a, b])).toThrow(/Could not find the migrations folder/);
    expect(() => resolveMigrationsDir([a, b])).toThrow(/nope-a/);
    expect(() => resolveMigrationsDir([a, b])).toThrow(/nope-b/);
  });

  it("offers the container layout before the source layout", () => {
    const c = migrationsDirCandidates({}, "/app");
    expect(c[0]).toBe(path.join("/app", "lib", "db", "migrations"));
    expect(c[1]).toBe(path.join("/app", "migrations"));
  });

  it("puts MIGRATIONS_DIR first when it is set", () => {
    expect(migrationsDirCandidates({ MIGRATIONS_DIR: "/custom" }, "/app")[0]).toBe("/custom");
  });
});

describe("the advisory lock key", () => {
  // Two processes only serialise if they contend on the SAME key, and the
  // namespace is shared with anything else using this database (pg-boss
  // included) — so it must not drift and must not be a value something else
  // would plausibly pick.
  it("is a fixed, non-obvious 64-bit value", () => {
    expect(MIGRATION_ADVISORY_LOCK_KEY).toBe(8_147_390_215_674_113n);
    expect(MIGRATION_ADVISORY_LOCK_KEY).toBeGreaterThan(1_000_000n);
  });
});
