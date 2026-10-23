import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // Many suites call vi.resetModules() and re-import a route per test, which
    // pulls the db, drizzle and the route's whole graph in cold. On a loaded
    // machine that import alone could pass vitest's 5s default, and a timed-out
    // test's still-running body then called the NEXT test's fetch mock ("called
    // 2 times") — failures that looked like logic bugs and were not. A real
    // hang still fails, at 20s.
    testTimeout: 20_000,
    hookTimeout: 30_000,
    // The scan HTTP layer refuses private addresses, and almost every probe
    // test drives it against a loopback server. This is the same switch a
    // self-hosted operator sets to scan their own network — the guard itself is
    // tested with the switch off, in ssrfGuard.test.ts, and the redirect case
    // (a hop that points at an internal address is refused) is in
    // http.blocked.test.ts, which turns the switch off itself.
    env: {
      ALLOW_PRIVATE_SCAN_TARGETS: "true",
      // @workspace/db throws at import time without this, so any test that
      // imports a route — which imports the db — fails before it runs. pg.Pool
      // connects lazily, so a string that resolves nowhere costs nothing and
      // touches no network. Tests needing real data still have to provide their
      // own database.
      DATABASE_URL: "postgresql://placeholder:placeholder@127.0.0.1:1/placeholder",
    },
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/index.ts"],
      reporter: ["text", "lcov"],
    },
  },
});
