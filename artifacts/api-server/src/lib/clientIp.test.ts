import { describe, it, expect, afterEach } from "vitest";
import type { Request } from "express";
import { clientIp, behindCloudflare } from "./clientIp";

/**
 * Express has already applied `trust proxy` by the time req.ip exists, so these
 * tests supply req.ip directly — the question here is which source wins, not how
 * Express derives one of them.
 */
function makeReq(opts: {
  ip?: string;
  headers?: Record<string, string>;
  remoteAddress?: string;
}): Request {
  return {
    ip: opts.ip,
    headers: opts.headers ?? {},
    socket: { remoteAddress: opts.remoteAddress },
  } as unknown as Request;
}

afterEach(() => {
  delete process.env["BEHIND_CLOUDFLARE"];
});

describe("clientIp", () => {
  it("uses req.ip, which honours the trust proxy hop count", () => {
    const req = makeReq({
      ip: "203.0.113.9",
      // A client-supplied chain. Express has already decided how much of this to
      // believe; we must not re-parse it and undo that.
      headers: { "x-forwarded-for": "1.2.3.4, 203.0.113.9" },
    });
    expect(clientIp(req)).toBe("203.0.113.9");
  });

  it("ignores a spoofed X-Forwarded-For entirely", () => {
    // The old implementation returned "9.9.9.9" here, letting a client mint a
    // fresh identity per request and walk straight through the limiter.
    const req = makeReq({
      ip: "203.0.113.9",
      headers: { "x-forwarded-for": "9.9.9.9" },
    });
    expect(clientIp(req)).toBe("203.0.113.9");
  });

  it("falls back to the socket address when there is no req.ip", () => {
    expect(clientIp(makeReq({ remoteAddress: "198.51.100.7" }))).toBe("198.51.100.7");
  });

  it("returns a stable placeholder rather than undefined when nothing is known", () => {
    expect(clientIp(makeReq({}))).toBe("unknown");
  });

  describe("behind Cloudflare", () => {
    it("prefers CF-Connecting-IP once opted in", () => {
      process.env["BEHIND_CLOUDFLARE"] = "true";
      const req = makeReq({
        ip: "172.71.0.1", // a Cloudflare edge address
        headers: { "cf-connecting-ip": "203.0.113.55" },
      });
      expect(clientIp(req)).toBe("203.0.113.55");
    });

    it("ignores CF-Connecting-IP when not opted in", () => {
      // On a directly reachable origin this header is just something a client
      // typed, so trusting it would be strictly worse than not having it.
      const req = makeReq({
        ip: "203.0.113.9",
        headers: { "cf-connecting-ip": "9.9.9.9" },
      });
      expect(clientIp(req)).toBe("203.0.113.9");
    });

    it("falls back to req.ip for a request that did not come through Cloudflare", () => {
      process.env["BEHIND_CLOUDFLARE"] = "true";
      const req = makeReq({ ip: "203.0.113.9" });
      expect(clientIp(req)).toBe("203.0.113.9");
    });

    it("ignores a blank CF-Connecting-IP", () => {
      process.env["BEHIND_CLOUDFLARE"] = "true";
      const req = makeReq({ ip: "203.0.113.9", headers: { "cf-connecting-ip": "   " } });
      expect(clientIp(req)).toBe("203.0.113.9");
    });

    it("is off unless the flag is exactly \"true\"", () => {
      process.env["BEHIND_CLOUDFLARE"] = "1";
      expect(behindCloudflare()).toBe(false);
    });
  });
});
