import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // The scan HTTP layer refuses private addresses, and almost every probe
    // test drives it against a loopback server. This is the same switch a
    // self-hosted operator sets to scan their own network — the guard itself is
    // tested with the switch off, in ssrfGuard.test.ts and in the redirect case
    // in http.test.ts.
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
