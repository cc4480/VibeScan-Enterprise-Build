import { describe, it, expect } from "vitest";
import { NEW_CATEGORY_LABELS } from "./summary-category-labels.js";

/**
 * The "Also detected:" line on the report cover names each category that has
 * findings. A category holds several checks, so its label has to describe all
 * of them. "Transport Security" once read "HTTP redirect, HSTS" while the real
 * finding was deprecated TLS versions, which sent a reader looking for a
 * problem that was not there.
 */
describe("NEW_CATEGORY_LABELS", () => {
  it("names TLS for Transport Security, which holds the TLS configuration check", () => {
    expect(NEW_CATEGORY_LABELS["Transport Security"]).toMatch(/TLS/);
  });

  it("names headers and cookies for HTTP Security, not only HTTP methods", () => {
    const label = NEW_CATEGORY_LABELS["HTTP Security"];
    expect(label).toMatch(/headers/);
    expect(label).toMatch(/cookies/);
    expect(label).toMatch(/methods/);
  });

  it("mentions the server version in Information Disclosure", () => {
    expect(NEW_CATEGORY_LABELS["Information Disclosure"]).toMatch(/server version/);
  });
});
