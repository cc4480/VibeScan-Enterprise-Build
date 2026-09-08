import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkSpf, checkDmarc, checkDkim, COMMON_DKIM_SELECTORS } from "./dnsChecks.js";

/**
 * DNS check tests — stubs globalThis.fetch to simulate Cloudflare DoH responses.
 * All tests use status=0 (NOERROR) to exercise the actual check logic,
 * not the "network failure" early-return path.
 */

// ─── DoH mock helpers ─────────────────────────────────────────────────────────

const TXT = 16, MX = 15, CNAME = 5;

/**
 * A real DoH answer section always carries the record type, and it contains the
 * whole resolution chain rather than only the type asked for. The fixtures omitted
 * `type` entirely, which is why a CNAME being counted as an MX record could not
 * have been caught here.
 */
function dohResponse(answers: { data: string; type?: number }[], status = 0, defaultType = TXT): Response {
  const Answer = answers.map((a) => ({
    name: "example.com",
    type: a.type ?? defaultType,
    TTL: 300,
    data: a.data,
  }));
  return new Response(JSON.stringify({ Status: status, Answer }), {
    status: 200,
    headers: { "content-type": "application/dns-json" },
  });
}

const noTxt = () => dohResponse([]);
const noMx  = () => dohResponse([]);
const hasMx = () => dohResponse([{ data: "10 mail.example.com.", type: MX }], 0, MX);

// ─── Setup / teardown ─────────────────────────────────────────────────────────

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── checkSpf — missing record ───────────────────────────────────────────────

describe("checkSpf — missing record", () => {
  it("returns one high-severity vuln when SPF is missing and MX records exist", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(noTxt())  // TXT query → no SPF
      .mockResolvedValueOnce(hasMx()); // MX query  → sends mail

    const vulns = await checkSpf("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("high");
    expect(vulns[0].name).toMatch(/missing spf/i);
    expect(vulns[0].cweId).toBe("CWE-290");
  });

  it("returns medium severity when SPF is missing and no MX records", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(noTxt())
      .mockResolvedValueOnce(noMx());

    const vulns = await checkSpf("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("medium");
  });

  it("returns empty array on network failure (status -1)", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network error"));
    expect(await checkSpf("example.com")).toEqual([]);
  });
});

// ─── checkSpf — dangerous configurations ─────────────────────────────────────

describe("checkSpf — dangerous configurations", () => {
  it("flags +all (permits any sender) as critical", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=spf1 include:_spf.google.com +all" }]),
    );
    const vulns = await checkSpf("example.com");
    expect(vulns.some((v) => v.severity === "critical" && v.name.includes("+all"))).toBe(true);
  });

  it("flags ?all (neutral — no enforcement) as medium", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=spf1 include:_spf.google.com ?all" }]),
    );
    const vulns = await checkSpf("example.com");
    expect(vulns.some((v) => v.severity === "medium" && v.name.includes("?all"))).toBe(true);
  });

  it("flags SPF that exceeds 8 DNS lookups as low", async () => {
    const manyIncludes =
      "v=spf1 " +
      "include:a.com include:b.com include:c.com include:d.com include:e.com " +
      "include:f.com include:g.com include:h.com include:i.com -all";
    vi.mocked(fetch).mockResolvedValueOnce(dohResponse([{ data: manyIncludes }]));
    const vulns = await checkSpf("example.com");
    expect(vulns.some((v) => /lookup limit/i.test(v.name))).toBe(true);
  });

  it("returns no vulns for a well-formed SPF record with -all", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=spf1 include:_spf.google.com -all" }]),
    );
    expect(await checkSpf("example.com")).toHaveLength(0);
  });

  it("returns no vulns for ~all (soft fail — acceptable)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=spf1 include:_spf.google.com ~all" }]),
    );
    expect(await checkSpf("example.com")).toHaveLength(0);
  });
});

// ─── checkDmarc — missing record ─────────────────────────────────────────────

describe("checkDmarc — missing record", () => {
  it("returns one high-severity vuln when DMARC record is missing", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(noTxt());
    const vulns = await checkDmarc("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("high");
    expect(vulns[0].name).toMatch(/missing dmarc/i);
  });

  it("returns empty array on network failure", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network error"));
    expect(await checkDmarc("example.com")).toEqual([]);
  });
});

// ─── checkDmarc — policy enforcement ─────────────────────────────────────────

describe("checkDmarc — policy enforcement", () => {
  it("flags p=none (monitoring only) as medium", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=DMARC1; p=none; rua=mailto:dmarc@example.com" }]),
    );
    const vulns = await checkDmarc("example.com");
    expect(vulns.some((v) => v.severity === "medium" && /none/i.test(v.name))).toBe(true);
  });

  it("flags missing rua= as info", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=DMARC1; p=quarantine" }]),
    );
    const vulns = await checkDmarc("example.com");
    expect(vulns.some((v) => v.severity === "info" && /rua/i.test(v.name))).toBe(true);
  });

  it("returns no vulns for a fully enforced DMARC record with rua=", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com" }]),
    );
    expect(await checkDmarc("example.com")).toHaveLength(0);
  });

  it("flags p=none AND missing rua= as two separate findings", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      dohResponse([{ data: "v=DMARC1; p=none" }]),
    );
    const vulns = await checkDmarc("example.com");
    expect(vulns.length).toBeGreaterThanOrEqual(2);
  });
});

describe("checkDkim", () => {
  it("carries the resend selector", () => {
    // Regression: secscan.us's own DKIM record lives at resend._domainkey and
    // was missing from this list, which would have made this checker report
    // "No DKIM" against a domain actively sending signed, delivering mail.
    expect(COMMON_DKIM_SELECTORS).toContain("resend");
  });

  it("finds a record under the resend selector and reports nothing", async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("resend._domainkey")) {
        return dohResponse([{ data: '"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB..."' }]);
      }
      return noTxt();
    });

    const vulns = await checkDkim("secscan.us");
    expect(vulns).toEqual([]);
  });

  it("still reports when every selector, including resend, comes back empty", async () => {
    vi.mocked(fetch).mockImplementation(async () => noTxt());

    const vulns = await checkDkim("example.com");
    expect(vulns.length).toBe(1);
    expect(vulns[0]!.name).toMatch(/No DKIM/i);
  });
});

// ─── Regressions from the 30-site corpus run (2026-09-08) ────────────────────
//
// All three were found in one finding: "Missing SPF Record" reported HIGH
// against www.gov.uk, which publishes v=spf1 -all at gov.uk and p=reject at
// _dmarc.gov.uk. Each is a separate bug and each gets its own test.

describe("email records are looked up at parent domains too", () => {
  it("finds SPF on the parent when the scanned host is www (the www.gov.uk case)", async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      // Only the parent carries the record, exactly as GOV.UK publishes it.
      if (url.includes("name=gov.uk") && !url.includes("www.gov.uk")) {
        return dohResponse([{ data: "v=spf1 -all" }]);
      }
      return noTxt();
    });

    expect(await checkSpf("www.gov.uk")).toEqual([]);
  });

  it("finds DMARC on the parent when the scanned host is www", async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("_dmarc.gov.uk")) {
        // GOV.UK's record as actually published, rua and all.
        return dohResponse([{
          data: "v=DMARC1;p=reject;sp=none;np=reject;adkim=s;aspf=s;fo=1;rua=mailto:dmarc-rua@dmarc.service.gov.uk",
        }]);
      }
      return noTxt();
    });

    expect(await checkDmarc("www.gov.uk")).toEqual([]);
  });

  it("still reports when neither the host nor any parent has a record", async () => {
    vi.mocked(fetch).mockImplementation(async () => noTxt());

    const vulns = await checkDmarc("www.example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.name).toMatch(/missing dmarc/i);
  });
});

describe("answers are matched against the record type that was asked for", () => {
  it("does not count CNAMEs in an MX answer as mail servers", async () => {
    // www.gov.uk is a CNAME to Fastly; its MX query answers with two CNAMEs and
    // no MX at all. Counting those escalated the finding from Medium to High.
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("type=MX")) {
        return dohResponse(
          [
            { data: "www-cdn.production.govuk.service.gov.uk.", type: CNAME },
            { data: "www-gov-uk.map.fastly.net.", type: CNAME },
          ],
          0,
          CNAME,
        );
      }
      return noTxt();
    });

    const vulns = await checkSpf("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("medium");
    expect(vulns[0]!.evidence).not.toMatch(/MX records present/);
  });
});

describe("evidence reports the status the resolver actually returned", () => {
  it("does not claim NOERROR, or report at all, when the name does not exist", async () => {
    // _dmarc.www.gov.uk is NXDOMAIN. The evidence string used to say
    // "Status: NOERROR (domain exists)" regardless of what came back.
    vi.mocked(fetch).mockImplementation(async () => dohResponse([], 3));

    expect(await checkDmarc("www.gov.uk")).toEqual([]);
  });

  it("names every domain it queried in the evidence", async () => {
    vi.mocked(fetch).mockImplementation(async () => noTxt());

    const vulns = await checkDmarc("www.example.com");
    expect(vulns[0]!.evidence).toMatch(/_dmarc\.www\.example\.com/);
    expect(vulns[0]!.evidence).toMatch(/_dmarc\.example\.com/);
    expect(vulns[0]!.evidence).toMatch(/NOERROR/);
  });
});
