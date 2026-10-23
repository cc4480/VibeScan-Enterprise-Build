import { describe, it, expect } from "vitest";
import { Writable } from "node:stream";
import pino from "pino";
import { checkProductionConfig } from "./bootChecks";

/** A real logger whose output is captured, so a test can count what was actually logged at error level. */
function capturedLogger() {
  const lines: string[] = [];
  const log = pino({ level: "info" }, new Writable({ write(chunk, _enc, cb) { lines.push(String(chunk)); cb(); } }));
  return { log, errors: () => lines.filter((l) => JSON.parse(l).level >= 50) };
}

const good = Buffer.alloc(32, 1).toString("base64");

describe("checkProductionConfig", () => {
  it("does nothing outside production", () => {
    const { log, errors } = capturedLogger();
    expect(() => checkProductionConfig(log, { NODE_ENV: "development" })).not.toThrow();
    expect(() => checkProductionConfig(log, {})).not.toThrow();
    expect(errors()).toHaveLength(0);
  });

  it("refuses to boot in production without ENCRYPTION_KEY", () => {
    expect(() => checkProductionConfig(capturedLogger().log, { NODE_ENV: "production" })).toThrow(/ENCRYPTION_KEY is required/);
    expect(() => checkProductionConfig(capturedLogger().log, { NODE_ENV: "production", ENCRYPTION_KEY: "   " })).toThrow(/required/);
  });

  it("accepts a 32-byte base64 key quietly", () => {
    const { log, errors } = capturedLogger();
    expect(() => checkProductionConfig(log, { NODE_ENV: "production", ENCRYPTION_KEY: good })).not.toThrow();
    expect(errors()).toHaveLength(0);
  });

  it("reports a key of the wrong length loudly but still boots", () => {
    const { log, errors } = capturedLogger();
    expect(() => checkProductionConfig(log, { NODE_ENV: "production", ENCRYPTION_KEY: "short" })).not.toThrow();
    expect(errors()).toHaveLength(1);
  });
});
