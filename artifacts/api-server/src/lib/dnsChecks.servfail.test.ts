import { useDohStub, txt } from "./dohStub.testkit";
import { describe, it, expect } from "vitest";
import { checkSpf } from "./dnsChecks.js";
import { dnsQuery } from "./dnsChecksCore.js";

// The resolver is a real DNS-over-HTTPS server on loopback (lib/dohStub.testkit.ts); its flaky answers are queued per name.
const doh = await useDohStub();

/**
 * Found by the 2026-09-30 re-sweep: about one scan in five reported nasa.gov as having no SPF record.
 * nasa.gov's TXT lookup returns SERVFAIL roughly one time in ten. The chain www.nasa.gov -> nasa.gov
 * decided "absent" from the first name (a clean NOERROR with nothing on it) and ignored that the parent,
 * where the record actually lives, had errored.
 */
const servfail = { status: 2, answers: [] };
const spf = (data: string) => ({ status: 0, answers: txt(data) });
const timesAsked = (name: string) => doh.asked.filter((q) => q === `${name} TXT`).length;

describe("dnsQuery retries a SERVFAIL once", () => {
  it("returns the answer from the retry", async () => {
    doh.queue("nasa.gov", "TXT", [servfail, spf("v=spf1 -all")]);
    const r = await dnsQuery("nasa.gov", "TXT");
    expect(r.status).toBe(0);
    expect(r.answers).toHaveLength(1);
    expect(timesAsked("nasa.gov")).toBe(2);
  });

  it("passes a second SERVFAIL on as SERVFAIL, and does not retry a clean answer", async () => {
    doh.queue("nasa.gov", "TXT", [servfail, servfail]);
    expect((await dnsQuery("nasa.gov", "TXT")).status).toBe(2);
    expect(timesAsked("nasa.gov")).toBe(2);

    doh.asked.length = 0;
    expect((await dnsQuery("nasa.gov", "TXT")).status).toBe(0);
    expect(timesAsked("nasa.gov")).toBe(1);
  });
});

describe("checkSpf up the domain chain", () => {
  it("makes no 'missing SPF' claim when the parent lookup keeps failing", async () => {
    // www.example.com answers cleanly with no TXT; example.com (where SPF lives) returns SERVFAIL twice.
    doh.queue("example.com", "TXT", [servfail, servfail]);
    expect(await checkSpf("www.example.com")).toEqual([]);
  });

  it("finds the record when the parent's first answer was a SERVFAIL and the retry succeeded", async () => {
    doh.queue("example.com", "TXT", [servfail, spf("v=spf1 include:_spf.example.net -all")]);
    expect(await checkSpf("www.example.com")).toEqual([]);
    expect(timesAsked("www.example.com")).toBe(1);
    expect(timesAsked("example.com")).toBe(2);
  });

  it("still reports SPF as missing when every name in the chain answered cleanly with nothing", async () => {
    const vulns = await checkSpf("www.example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.name).toMatch(/missing spf/i);
  });
});
