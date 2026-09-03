import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// oobServer.ts imports @workspace/db at module scope, which throws unless
// DATABASE_URL exists, before any exported function runs. pg.Pool connects
// lazily — constructing it with a string that resolves nowhere does not touch
// the network — so a placeholder here is sufficient for the two pure
// functions under test and does not require a real database.
process.env["DATABASE_URL"] ||= "postgresql://placeholder:placeholder@127.0.0.1:1/placeholder";

describe("oobBaseUrl", () => {
  const original = { ...process.env };

  beforeEach(() => {
    delete process.env["OOB_BASE_URL"];
    delete process.env["APP_ORIGIN"];
    vi.resetModules();
  });

  afterEach(() => {
    process.env = { ...original };
  });

  it("uses OOB_BASE_URL when set, trailing slash trimmed", async () => {
    process.env["OOB_BASE_URL"] = "https://collector.example/";
    const { oobBaseUrl } = await import("./oobServer.js");
    expect(oobBaseUrl()).toBe("https://collector.example");
  });

  it("falls back to APP_ORIGIN when OOB_BASE_URL is unset", async () => {
    process.env["APP_ORIGIN"] = "https://app.example";
    const { oobBaseUrl } = await import("./oobServer.js");
    expect(oobBaseUrl()).toBe("https://app.example");
  });

  it("prefers OOB_BASE_URL over APP_ORIGIN when both are set", async () => {
    process.env["OOB_BASE_URL"] = "https://collector.example";
    process.env["APP_ORIGIN"] = "https://app.example";
    const { oobBaseUrl } = await import("./oobServer.js");
    expect(oobBaseUrl()).toBe("https://collector.example");
  });

  it("does not treat a localhost APP_ORIGIN as configured", async () => {
    // A dev APP_ORIGIN is never reachable by a real target, so it must not be
    // planted as a callback URL that can only fail.
    process.env["APP_ORIGIN"] = "http://localhost:8080";
    const { oobBaseUrl, isOobConfigured } = await import("./oobServer.js");
    expect(oobBaseUrl()).toBe("");
    expect(isOobConfigured()).toBe(false);
  });

  it("does not apply that guard to an explicit OOB_BASE_URL", async () => {
    // An operator pointing the collector at localhost on purpose — the exact
    // shape used to test this feature locally — must be honoured, not silently
    // disabled by the same guard that protects APP_ORIGIN.
    process.env["OOB_BASE_URL"] = "http://localhost:8080";
    const { oobBaseUrl, isOobConfigured } = await import("./oobServer.js");
    expect(oobBaseUrl()).toBe("http://localhost:8080");
    expect(isOobConfigured()).toBe(true);
  });

  it("is unconfigured when neither variable is set", async () => {
    const { isOobConfigured } = await import("./oobServer.js");
    expect(isOobConfigured()).toBe(false);
  });
});
