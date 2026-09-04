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

  it("does not trust CF-Connecting-IP on its own when nothing proves the hop", () => {
    // No secret and no Cloudflare-range hop: there is nothing establishing that
    // Cloudflare was in front, so fall back to req.ip rather than believing a
    // header any client can send.
    const req = makeReq({ "cf-connecting-ip": "198.51.100.20" });
    expect(clientIp(req)).toBe("203.0.113.9");
  });

  it("trusts CF-Connecting-IP when the last hop is a Cloudflare address", () => {
    // The proof that needs no configuration: 172.68.x is Cloudflare, and the
    // platform router — not the client — wrote that final entry.
    const req = makeReq({
      "cf-connecting-ip": "198.51.100.20",
      "x-forwarded-for": "198.51.100.20, 172.68.14.1",
    });
    expect(clientIp(req)).toBe("198.51.100.20");
  });

  it("ignores a Cloudflare address the client merely prepended", () => {
    // Forging the header does not help: only the final entry is consulted, and
    // that one the client cannot write.
    const req = makeReq({
      "cf-connecting-ip": "1.2.3.4",
      "x-forwarded-for": "172.68.14.1, 9.9.9.9",
    });
    expect(clientIp(req)).toBe("203.0.113.9");
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
