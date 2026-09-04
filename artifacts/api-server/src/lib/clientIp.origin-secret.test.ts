import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { Request } from "express";
import { clientIp } from "./clientIp";

/**
 * The platform case: the origin keeps a public hostname (a *.up.railway.app
 * URL, say) that anyone can reach, so "arrived at the origin" proves nothing
 * about having come through Cloudflare.
 */
function makeReq(headers: Record<string, string>, ip = "203.0.113.9"): Request {
  return { ip, headers, socket: {} } as unknown as Request;
}

const SECRET = "s3cret-value-from-cloudflare-transform-rule";

beforeEach(() => {
  process.env["BEHIND_CLOUDFLARE"] = "true";
});

afterEach(() => {
  delete process.env["BEHIND_CLOUDFLARE"];
  delete process.env["CLOUDFLARE_ORIGIN_SECRET"];
});

describe("origin secret", () => {
  it("trusts CF-Connecting-IP when the secret matches", () => {
    process.env["CLOUDFLARE_ORIGIN_SECRET"] = SECRET;
    const req = makeReq({
      "cf-connecting-ip": "198.51.100.20",
      "x-origin-secret": SECRET,
    });
    expect(clientIp(req)).toBe("198.51.100.20");
  });

  it("ignores CF-Connecting-IP when the secret is absent", () => {
    // This is the attack the secret exists to stop: a request sent straight to
    // the platform hostname, carrying a forged client address.
    process.env["CLOUDFLARE_ORIGIN_SECRET"] = SECRET;
    const req = makeReq({ "cf-connecting-ip": "198.51.100.20" });
    expect(clientIp(req)).toBe("203.0.113.9");
  });

  it("ignores CF-Connecting-IP when the secret is wrong", () => {
    process.env["CLOUDFLARE_ORIGIN_SECRET"] = SECRET;
    const req = makeReq({
      "cf-connecting-ip": "198.51.100.20",
      "x-origin-secret": "not-the-secret-but-same-length-padding!!",
    });
    expect(clientIp(req)).toBe("203.0.113.9");
  });

  it("ignores a secret of the wrong length without throwing", () => {
    // timingSafeEqual throws on mismatched lengths; that must not surface as a
    // 500 on a request an attacker fully controls.
    process.env["CLOUDFLARE_ORIGIN_SECRET"] = SECRET;
    const req = makeReq({
      "cf-connecting-ip": "198.51.100.20",
      "x-origin-secret": "short",
    });
    expect(() => clientIp(req)).not.toThrow();
    expect(clientIp(req)).toBe("203.0.113.9");
  });

  it("takes the first value when the header is sent more than once", () => {
    process.env["CLOUDFLARE_ORIGIN_SECRET"] = SECRET;
    const req = {
      ip: "203.0.113.9",
      headers: {
        "cf-connecting-ip": "198.51.100.20",
        "x-origin-secret": [SECRET, "decoy"],
      },
      socket: {},
    } as unknown as Request;
    expect(clientIp(req)).toBe("198.51.100.20");
  });

  it("keeps trusting Cloudflare when no secret is configured", () => {
    // The firewalled-origin deployment: reaching the origin is itself the proof,
    // so requiring a header there would break a working setup.
    const req = makeReq({ "cf-connecting-ip": "198.51.100.20" });
    expect(clientIp(req)).toBe("198.51.100.20");
  });

  it("does not consult the secret at all when Cloudflare is not in front", () => {
    delete process.env["BEHIND_CLOUDFLARE"];
    process.env["CLOUDFLARE_ORIGIN_SECRET"] = SECRET;
    const req = makeReq({
      "cf-connecting-ip": "9.9.9.9",
      "x-origin-secret": SECRET,
    });
    expect(clientIp(req)).toBe("203.0.113.9");
  });
});
