import { defineConfig } from "vitest/config";
import path from "path";

/**
 * Frontend tests.
 *
 * Deliberately node-environment rather than jsdom: what is worth testing here
 * is the logic that decides things — whether a form is complete, which error to
 * show, what identity the browser sends — not whether React renders a div.
 * Adding jsdom and a component-testing stack for that would be a lot of
 * machinery around assertions that mostly restate the JSX.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "src") },
  },
});
