import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // The scan HTTP layer refuses private addresses, and almost every probe
    // test drives it against a loopback server. This is the same switch a
    // self-hosted operator sets to scan their own network — the guard itself is
    // tested with the switch off, in ssrfGuard.test.ts and in the redirect case
    // in http.test.ts.
    env: { ALLOW_PRIVATE_SCAN_TARGETS: "true" },
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/index.ts"],
      reporter: ["text", "lcov"],
    },
  },
});
