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
 *
 * The exception is a component whose output is the point (a report section that
 * must say what was and was not read): it is rendered to a string with
 * react-dom/server in this same node environment, in a .test.tsx file. That needs
 * no DOM and no extra libraries.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
  },
  // The same JSX transform the app is built with, so a .test.tsx renders without importing React.
  esbuild: { jsx: "automatic" },
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "src") },
  },
});
