import { describe, it, expect } from "vitest";
import { isSpaRoute } from "./spaRoutes";

/**
 * The failure this guards against is not a broken page — it is the site's
 * shape. A fallback that answers 200 plus a sign-in form on unlimited distinct
 * URLs reads as a credential-harvesting kit to a classifier, which is what got
 * seclayer.app flagged domain-wide by Google Safe Browsing.
 */
describe("isSpaRoute", () => {
  it("serves the shell for every route the client renders", () => {
    for (const path of [
      "/",
      "/dashboard",
      "/scan",
      "/monitor",
      "/learn",
      "/bot",
      "/domains",
      "/settings",
      "/feedback",
      "/privacy",
      "/terms",
      "/sign-in",
      "/register",
      "/forgot-password",
      "/reset-password",
      "/verify-email",
      "/oauth/authorize",
    ]) {
      expect(isSpaRoute(path), path).toBe(true);
    }
  });

  it("serves the shell for parameterised routes", () => {
    expect(isSpaRoute("/scan/8a55c3b2-6f28-4822-97f4-bdc829dd3858")).toBe(true);
    expect(isSpaRoute("/report/abc123")).toBe(true);
    expect(isSpaRoute("/share/Xy_9-Zq")).toBe(true);
  });

  it("serves the shell for trust pages, whose address is a domain with dots, and for the team pages", () => {
    for (const path of [
      "/trust/shop.example.com",
      "/trust/shop.example.com/",
      "/trust/a-b.example.co.uk",
      "/trust/Shop.Example.COM",
      "/team/accept",
      "/team/accept/",
      "/team/shared/3f1c0d52-8a41-4c1e-9d3b-0a5e2c7e9f10",
    ]) {
      expect(isSpaRoute(path), path).toBe(true);
    }
  });

  it("refuses trust paths that are not a well-formed domain, and team paths that are not pages", () => {
    for (const path of [
      "/trust", "/trust/", "/trust/localhost", "/trust/a..b", "/trust/-a.example.com", "/trust/a-.example.com", "/trust/.example.com",
      "/trust/example.com/extra", "/trust/exa mple.com", `/trust/${"a".repeat(64)}.com`, "/trust/shop.example.com%2F..", "/trust/shop.example.com.",
      "/team", "/team/", "/team/accept/extra", "/team/shared", "/team/shared/", "/team/shared/a/b", "/team/members",
    ]) {
      expect(isSpaRoute(path), path).toBe(false);
    }
  });

  it("tolerates a trailing slash", () => {
    expect(isSpaRoute("/dashboard/")).toBe(true);
    expect(isSpaRoute("/privacy/")).toBe(true);
  });

  it("refuses the phishing-shaped paths that caused the original flag", () => {
    for (const path of [
      "/wp-login.php",
      "/admin/login",
      "/verify-account",
      "/secure/signin",
      "/wp-admin",
      "/login",
      "/signin",
    ]) {
      expect(isSpaRoute(path), path).toBe(false);
    }
  });

  it("refuses paths that merely start like a real route", () => {
    // A prefix match here would re-open the hole: /sign-in-now and
    // /dashboard/../wp-login.php are not routes the client renders.
    expect(isSpaRoute("/sign-in-now")).toBe(false);
    expect(isSpaRoute("/settings/billing")).toBe(false);
    expect(isSpaRoute("/report")).toBe(false);
    expect(isSpaRoute("/report/abc/extra")).toBe(false);
  });

  it("refuses API paths, which must answer as JSON not as the shell", () => {
    expect(isSpaRoute("/api/settings/deepseek-key")).toBe(false);
    expect(isSpaRoute("/api/does-not-exist")).toBe(false);
  });

  it("refuses asset-shaped paths so a missing file 404s honestly", () => {
    expect(isSpaRoute("/favicon.ico")).toBe(false);
    expect(isSpaRoute("/assets/missing.js")).toBe(false);
  });
});
