import { describe, it, expect } from "vitest";
import { detectPlatformGate, landedElsewhere } from "./platformGate";

const APP = "https://myapp.example.com/";

describe("detectPlatformGate: sign-in walls", () => {
  it.each([
    ["Cloudflare Access", "https://acme.cloudflareaccess.com/cdn-cgi/access/login/myapp.example.com?redirect_url=%2F"],
    ["Google sign-in", "https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmyapp.example.com"],
    ["Microsoft sign-in", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x"],
    ["Auth0", "https://acme.us.auth0.com/u/login?state=x"],
    ["Okta", "https://acme.okta.com/oauth2/default/v1/authorize"],
    ["GitHub sign-in", "https://github.com/login?return_to=%2Foauth"],
    ["Replit sign-in", "https://replit.com/auth_with_repl_site?domain=myapp.replit.app"],
    ["Vercel Deployment Protection", "https://vercel.com/sso-api?url=https%3A%2F%2Fmyapp.vercel.app"],
  ])("recognises a redirect to %s", (vendor, landed) => {
    const v = detectPlatformGate(APP, landed, 200, "<html><body><h1>Sign in</h1></body></html>");
    expect(v).toMatchObject({ isGate: true, kind: "sign-in wall", vendor });
  });

  it("recognises Vercel Deployment Protection served on the app's own host", () => {
    const html = `<!doctype html><html><head><title>Authentication Required</title></head><body><script>location.href="https://vercel.com/sso-api?url="+encodeURIComponent(location.href)</script></body></html>`;
    const v = detectPlatformGate("https://myapp.vercel.app/", "https://myapp.vercel.app/", 401, html, { server: "Vercel" });
    expect(v).toMatchObject({ isGate: true, kind: "sign-in wall", vendor: "Vercel Deployment Protection" });
  });

  it("does not call the identity provider's own site a gate when it is what was scanned", () => {
    expect(detectPlatformGate("https://github.com/", "https://github.com/login", 200, "<html></html>").isGate).toBe(false);
  });

  it("does not treat a working page that links to a sign-in path as a gate", () => {
    const html = `<html><body><nav><a href="https://vercel.com/sso-api">Team login</a></nav><h1>Welcome</h1></body></html>`;
    expect(detectPlatformGate(APP, APP, 200, html).isGate).toBe(false);
  });

  it("does not treat a redirect to github.com that is not its sign-in page as a gate", () => {
    expect(detectPlatformGate(APP, "https://github.com/acme/myapp", 200, "<html></html>").isGate).toBe(false);
  });
});

describe("detectPlatformGate: platform pages with no app behind them", () => {
  it.each([
    ["Vercel", { "x-vercel-error": "DEPLOYMENT_NOT_FOUND" }, 404],
    ["Vercel", { "x-vercel-error": "DEPLOYMENT_PAUSED" }, 503],
    ["Railway", { "x-railway-fallback": "true" }, 404],
    ["Render", { "x-render-routing": "no-server" }, 404],
  ])("recognises %s by its response header", (vendor, headers, status) => {
    expect(detectPlatformGate(APP, APP, status, "<html>Not found</html>", headers)).toMatchObject({ isGate: true, kind: "app not running", vendor });
  });

  it("ignores Vercel's NOT_FOUND for a missing page on a live deployment", () => {
    expect(detectPlatformGate(APP, APP, 404, "<html>404</html>", { "x-vercel-error": "NOT_FOUND" }).isGate).toBe(false);
  });

  it("recognises Heroku's application-error page, but only on an error status", () => {
    const html = `<html><body><iframe src="//www.herokucdn.com/error-pages/application-error.html"></iframe></body></html>`;
    expect(detectPlatformGate(APP, APP, 503, html)).toMatchObject({ isGate: true, vendor: "Heroku" });
    expect(detectPlatformGate(APP, APP, 200, html).isGate).toBe(false);
  });

  it("does not treat an ordinary site's own 404 as a platform page", () => {
    expect(detectPlatformGate(APP, APP, 404, "<html><title>Page not found</title><h1>Sorry</h1></html>").isGate).toBe(false);
  });
});

describe("landedElsewhere", () => {
  it("names the host when a redirect left the site", () => {
    expect(landedElsewhere("https://brand.com/", "https://other.io/home")).toBe("other.io");
  });
  it("ignores www and subdomain hops", () => {
    expect(landedElsewhere("https://brand.com/", "https://www.brand.com/")).toBeNull();
    expect(landedElsewhere("https://brand.com/", "https://app.brand.com/")).toBeNull();
    expect(landedElsewhere("https://www.brand.com/", "https://brand.com/")).toBeNull();
  });
});
