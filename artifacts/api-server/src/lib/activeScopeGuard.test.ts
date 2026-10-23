import { describe, it, expect } from "vitest";
import { activeProbesStillAllowed } from "./activeScopeGuard";

describe("activeProbesStillAllowed", () => {
  it("allows the submitted host itself without a further check", async () => {
    expect(await activeProbesStillAllowed("https://example.com/", "https://example.com/app")).toEqual({ allowed: true });
    expect(await activeProbesStillAllowed("https://example.com/", "http://EXAMPLE.com/")).toEqual({ allowed: true });
  });

  it("does not allow a subdomain of the submitted host unless that subdomain is verified", async () => {
    // A subdomain is not covered by verifying the parent: it must pass the same ownership check.
    const unverified = await activeProbesStillAllowed("https://example.com/", "https://www.example.com/");
    expect(unverified).toEqual({ allowed: false, redirectedTo: "www.example.com" });
    expect(await activeProbesStillAllowed("https://example.com/", "https://www.example.com/", async () => false))
      .toEqual({ allowed: false, redirectedTo: "www.example.com" });

    const asked: string[] = [];
    const verify = async (url: string) => { asked.push(url); return true; };
    expect(await activeProbesStillAllowed("https://example.com/", "https://www.example.com/", verify)).toEqual({ allowed: true });
    expect(asked).toEqual(["https://www.example.com/"]);
  });

  it("withdraws active probing when the site redirects to somebody else's host", async () => {
    const r = await activeProbesStillAllowed("https://evil.example/", "https://victim.test/");
    expect(r).toEqual({ allowed: false, redirectedTo: "victim.test" });
  });

  it("does not treat a lookalike suffix as a subdomain", async () => {
    expect((await activeProbesStillAllowed("https://myhost.com/", "https://notmyhost.com/")).allowed).toBe(false);
    expect((await activeProbesStillAllowed("https://myhost.com/", "https://myhost.com.evil.test/")).allowed).toBe(false);
  });

  it("withdraws it for www -> apex unless the apex is verified as well", async () => {
    expect((await activeProbesStillAllowed("https://www.example.com/", "https://example.com/")).allowed).toBe(false);
    const asked: string[] = [];
    const verify = async (url: string) => { asked.push(url); return true; };
    expect((await activeProbesStillAllowed("https://www.example.com/", "https://example.com/", verify)).allowed).toBe(true);
    expect(asked).toEqual(["https://example.com/"]);
  });

  it("fails closed when the verification lookup throws or says no", async () => {
    expect((await activeProbesStillAllowed("https://a.test/", "https://b.test/", async () => { throw new Error("db down"); })).allowed).toBe(false);
    expect((await activeProbesStillAllowed("https://a.test/", "https://b.test/", async () => false)).allowed).toBe(false);
  });

  it("fails closed on a URL it cannot read", async () => {
    expect((await activeProbesStillAllowed("https://a.test/", "not a url")).allowed).toBe(false);
    expect((await activeProbesStillAllowed("nope", "https://a.test/")).allowed).toBe(false);
  });
});
