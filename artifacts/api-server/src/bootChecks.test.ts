import { describe, it, expect, vi } from "vitest";
import { checkProductionConfig } from "./bootChecks";

const good = Buffer.alloc(32, 1).toString("base64");

describe("checkProductionConfig", () => {
  it("does nothing outside production", () => {
    const log = { error: vi.fn() };
    expect(() => checkProductionConfig(log, { NODE_ENV: "development" })).not.toThrow();
    expect(() => checkProductionConfig(log, {})).not.toThrow();
    expect(log.error).not.toHaveBeenCalled();
  });

  it("refuses to boot in production without ENCRYPTION_KEY", () => {
    expect(() => checkProductionConfig({ error: vi.fn() }, { NODE_ENV: "production" })).toThrow(/ENCRYPTION_KEY is required/);
    expect(() => checkProductionConfig({ error: vi.fn() }, { NODE_ENV: "production", ENCRYPTION_KEY: "   " })).toThrow(/required/);
  });

  it("accepts a 32-byte base64 key quietly", () => {
    const log = { error: vi.fn() };
    expect(() => checkProductionConfig(log, { NODE_ENV: "production", ENCRYPTION_KEY: good })).not.toThrow();
    expect(log.error).not.toHaveBeenCalled();
  });

  it("reports a key of the wrong length loudly but still boots", () => {
    const log = { error: vi.fn() };
    expect(() => checkProductionConfig(log, { NODE_ENV: "production", ENCRYPTION_KEY: "short" })).not.toThrow();
    expect(log.error).toHaveBeenCalledTimes(1);
  });
});
