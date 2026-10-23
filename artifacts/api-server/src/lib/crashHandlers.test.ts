import { describe, it, expect } from "vitest";
import { isRecoverableOutboundHttpError } from "./crashHandlers.js";

// The exact shape Node/undici produced on 2026-09-07 when nytimes.com closed
// the connection mid-response and crashed the scan worker.
function undiciParserAssertion(): Error {
  const e = new Error("false == true") as NodeJS.ErrnoException;
  e.name = "AssertionError";
  e.code = "ERR_ASSERTION";
  e.stack =
    "AssertionError [ERR_ASSERTION]: false == true\n" +
    "    at Parser.finish (node:internal/deps/undici/undici:7388:9)\n" +
    "    at Socket.onHttpSocketEnd (node:internal/deps/undici/undici:7827:34)\n" +
    "    at Socket.emit (node:events:526:24)\n" +
    "    at endReadableNT (node:internal/streams/readable:1757:12)";
  return e;
}

describe("isRecoverableOutboundHttpError", () => {
  it("recognises the undici parser assertion from connection teardown", () =>
    expect(isRecoverableOutboundHttpError(undiciParserAssertion())).toBe(true));

  it("does NOT swallow an ordinary application assertion", () => {
    const e = new Error("expected 1 to equal 2") as NodeJS.ErrnoException;
    e.code = "ERR_ASSERTION";
    e.stack =
      "AssertionError: expected 1 to equal 2\n" +
      "    at Object.<anonymous> (/app/src/lib/scoring.ts:42:10)";
    expect(isRecoverableOutboundHttpError(e)).toBe(false);
  });

  it("does NOT swallow a generic TypeError from our own code", () => {
    const e = new TypeError("Cannot read properties of undefined (reading 'x')");
    e.stack = "TypeError: ...\n    at analyze (/app/src/lib/scanner.ts:10:1)";
    expect(isRecoverableOutboundHttpError(e)).toBe(false);
  });

  it("does NOT swallow an assertion whose stack merely mentions undici in a message", () => {
    const e = new Error("undici is great") as NodeJS.ErrnoException;
    e.code = "ERR_ASSERTION";
    e.stack = "AssertionError: undici is great\n    at foo (/app/src/x.ts:1:1)";
    expect(isRecoverableOutboundHttpError(e)).toBe(false);
  });

  it("ignores non-Error values", () => {
    expect(isRecoverableOutboundHttpError("false == true")).toBe(false);
    expect(isRecoverableOutboundHttpError(null)).toBe(false);
    expect(isRecoverableOutboundHttpError({ code: "ERR_ASSERTION" })).toBe(false);
  });
});
