import { describe, it, expect } from "vitest";
import { reproSteps } from "./repro-steps";

describe("reproSteps", () => {
  it("replays a plain GET with the response the scanner saw", () => {
    const r = reproSteps("GET https://example.com/.env → HTTP 200 (1,204 bytes)\nContent-Type: text/plain");
    expect(r?.command).toBe("curl -i 'https://example.com/.env'");
    expect(r?.expect).toEqual(["HTTP 200 (1,204 bytes)"]);
  });

  it("replays OPTIONS", () => {
    expect(reproSteps("OPTIONS https://example.com/api\nAllow: GET, PUT, DELETE")?.command).toBe(
      "curl -i -X OPTIONS 'https://example.com/api'",
    );
  });

  it("replays the request header the CORS test sent, and lists the response lines to look for", () => {
    const r = reproSteps(
      "GET https://example.com/api\nRequest header: Origin: https://evil.example\nResponse: Access-Control-Allow-Origin: https://evil.example\nResponse: Access-Control-Allow-Credentials: true",
    );
    expect(r?.command).toBe("curl -i -H 'Origin: https://evil.example' 'https://example.com/api'");
    expect(r?.expect).toEqual(["Access-Control-Allow-Origin: https://evil.example", "Access-Control-Allow-Credentials: true"]);
  });

  it.each([
    ["a POST", "POST https://example.com/login\nbody: a=b"],
    ["free text", "Detected: jQuery 1.11.3"],
    ["a DNS record", "CNAME shop.example.com → foo.herokuapp.com"],
    ["an empty evidence", ""],
    ["a non-http URL", "GET ftp://example.com/x"],
    ["a URL with credentials", "GET https://user:pw@example.com/"],
    ["a URL with a quote in it", "GET https://example.com/a'b"],
    ["a header value with a quote", "GET https://example.com/\nRequest header: Origin: x'; rm -rf ~ #"],
    ["an evidence that does not start with a request", "Note\nGET https://example.com/"],
  ])("gives nothing for %s", (_n, evidence) => {
    expect(reproSteps(evidence)).toBeNull();
  });

  it("gives nothing for null and undefined", () => {
    expect(reproSteps(null)).toBeNull();
    expect(reproSteps(undefined)).toBeNull();
  });
});
