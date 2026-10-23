import { describe, it, expect } from "vitest";
import { staticCacheControl } from "./cachePolicy";

describe("static cache policy", () => {
  it("caches fingerprinted build assets for a year", () => {
    expect(staticCacheControl("/app/artifacts/vibescan/dist/public/assets/index-DbbKlkkT.js")).toBe("public, max-age=31536000, immutable");
    expect(staticCacheControl("C:\\app\\dist\\public\\assets\\index-CVO-oAEO.css")).toBe("public, max-age=31536000, immutable");
  });

  it("never caches HTML, so a deploy shows at once", () => {
    expect(staticCacheControl("/app/dist/public/index.html")).toBe("no-cache");
  });

  it("keeps verification files short-lived", () => {
    expect(staticCacheControl("/app/dist/public/.well-known/mcp-registry-auth")).toBe("public, max-age=300");
  });

  it("caches images and text files for a day", () => {
    expect(staticCacheControl("/app/dist/public/images/hero-bg.webp")).toBe("public, max-age=86400");
    expect(staticCacheControl("/app/dist/public/robots.txt")).toBe("public, max-age=86400");
  });
});
