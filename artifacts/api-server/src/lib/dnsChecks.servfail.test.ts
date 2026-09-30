import { TXT, dohResponse, noTxt, noMx } from "./dnsChecks.testkit";
import { describe, it, expect, vi } from "vitest";
import { checkSpf } from "./dnsChecks.js";
import { dnsQuery } from "./dnsChecksCore.js";

/**
 * Found by the 2026-09-30 re-sweep: about one scan in five reported nasa.gov as having no SPF record.
 * nasa.gov's TXT lookup returns SERVFAIL roughly one time in ten. The chain www.nasa.gov -> nasa.gov
 * decided "absent" from the first name (a clean NOERROR with nothing on it) and ignored that the parent,
 * where the record actually lives, had errored.
 */
const servfail = () => dohResponse([], 2);
const spf = (data: string) => dohResponse([{ data: `"${data}"`, type: TXT }]);

describe("dnsQuery retries a SERVFAIL once", () => {
  it("returns the answer from the retry", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(servfail()).mockResolvedValueOnce(spf("v=spf1 -all"));
    const r = await dnsQuery("nasa.gov", "TXT");
    expect(r.status).toBe(0);
    expect(r.answers).toHaveLength(1);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("passes a second SERVFAIL on as SERVFAIL, and does not retry a clean answer", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(servfail()).mockResolvedValueOnce(servfail());
    expect((await dnsQuery("nasa.gov", "TXT")).status).toBe(2);
    expect(fetch).toHaveBeenCalledTimes(2);

    vi.mocked(fetch).mockClear();
    vi.mocked(fetch).mockResolvedValueOnce(noTxt());
    expect((await dnsQuery("nasa.gov", "TXT")).status).toBe(0);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe("checkSpf up the domain chain", () => {
  it("makes no 'missing SPF' claim when the parent lookup keeps failing", async () => {
    // www.example.com answers cleanly with no TXT; example.com (where SPF lives) returns SERVFAIL twice.
    vi.mocked(fetch).mockResolvedValueOnce(noTxt()).mockResolvedValueOnce(servfail()).mockResolvedValueOnce(servfail());
    expect(await checkSpf("www.example.com")).toEqual([]);
  });

  it("finds the record when the parent's first answer was a SERVFAIL and the retry succeeded", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(noTxt()).mockResolvedValueOnce(servfail()).mockResolvedValueOnce(spf("v=spf1 include:_spf.example.net -all"));
    expect(await checkSpf("www.example.com")).toEqual([]);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("still reports SPF as missing when every name in the chain answered cleanly with nothing", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(noTxt()).mockResolvedValueOnce(noTxt()).mockResolvedValueOnce(noMx());
    const vulns = await checkSpf("www.example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.name).toMatch(/missing spf/i);
  });
});
