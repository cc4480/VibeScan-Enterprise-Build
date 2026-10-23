import { useDohStub, txt, CNAME, DNSKEY } from "./dohStub.testkit";
import { describe, it, expect } from "vitest";
import { checkSpf, checkDmarc, checkDnssec } from "./dnsChecks.js";

// The resolver is a real DNS-over-HTTPS server on loopback (lib/dohStub.testkit.ts); the zone is set in each test.
const doh = await useDohStub();

// ─── Regressions from the 30-site corpus run (2026-09-08) ────────────────────
//
// All three were found in one finding: "Missing SPF Record" reported HIGH
// against www.gov.uk, which publishes v=spf1 -all at gov.uk and p=reject at
// _dmarc.gov.uk. Each is a separate bug and each gets its own test.

describe("email records are looked up at parent domains too", () => {
  it("finds SPF on the parent when the scanned host is www (the www.gov.uk case)", async () => {
    // Only the parent carries the record, exactly as GOV.UK publishes it.
    doh.set("gov.uk", "TXT", txt("v=spf1 -all"));

    expect(await checkSpf("www.gov.uk")).toEqual([]);
  });

  it("finds DMARC on the parent when the scanned host is www", async () => {
    // GOV.UK's record as actually published, rua and all.
    doh.set("_dmarc.gov.uk", "TXT", txt("v=DMARC1;p=reject;sp=none;np=reject;adkim=s;aspf=s;fo=1;rua=mailto:dmarc-rua@dmarc.service.gov.uk"));

    expect(await checkDmarc("www.gov.uk")).toEqual([]);
  });

  it("still reports when neither the host nor any parent has a record", async () => {
    const vulns = await checkDmarc("www.example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.name).toMatch(/missing dmarc/i);
  });
});

describe("answers are matched against the record type that was asked for", () => {
  it("does not count CNAMEs in an MX answer as mail servers", async () => {
    // www.gov.uk is a CNAME to Fastly; its MX query answers with two CNAMEs and
    // no MX at all. Counting those escalated the finding from Medium to High.
    doh.set("example.com", "MX", [
      { data: "www-cdn.production.govuk.service.gov.uk.", type: CNAME },
      { data: "www-gov-uk.map.fastly.net.", type: CNAME },
    ]);

    const vulns = await checkSpf("example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.severity).toBe("medium");
    expect(vulns[0]!.evidence).not.toMatch(/MX records present/);
  });
});

describe("evidence reports the status the resolver actually returned", () => {
  const nxdomain = { status: 3, answers: [] };

  it("treats an absent _dmarc label as an absent policy, not as an unknown", async () => {
    // Over-correction caught in the final run: suppressing on NXDOMAIN threw
    // away a TRUE finding. _dmarc.europa.eu is NXDOMAIN on two independent
    // resolvers and europa.eu has real MX records — it genuinely publishes no
    // DMARC policy, which is exactly what an absent _dmarc label means.
    doh.rule = () => nxdomain;

    const vulns = await checkDmarc("european-union.europa.eu");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.name).toMatch(/missing dmarc/i);
    expect(vulns[0]!.evidence).not.toMatch(/NOERROR/);
    expect(vulns[0]!.evidence).toMatch(/NXDOMAIN/);
  });

  it("withholds an SPF finding when the domain itself does not resolve", async () => {
    // SPF asks for the domain, not a sub-label: NXDOMAIN there means the
    // lookup did not describe reality, so no finding may be built on it.
    doh.rule = () => nxdomain;

    expect(await checkSpf("www.example.com")).toEqual([]);
  });

  it("names every domain it queried in the evidence", async () => {
    const vulns = await checkDmarc("www.example.com");
    expect(vulns[0]!.evidence).toMatch(/_dmarc\.www\.example\.com/);
    expect(vulns[0]!.evidence).toMatch(/_dmarc\.example\.com/);
    expect(vulns[0]!.evidence).toMatch(/NOERROR/);
  });
});

describe("DNSSEC is checked at the zone apex", () => {
  it("does not report a signed zone as unsigned when www is a CNAME", async () => {
    // www.nasa.gov answers a DNSKEY query with one CNAME and no DNSKEY, while
    // nasa.gov is signed. Filtering answers by type exposed this: before the
    // filter, the CNAME was counted as a DNSKEY and the check passed by accident.
    doh.rule = (name) =>
      name === "www.nasa.gov"
        ? { status: 0, answers: [{ data: "nasa-gov.edgekey.net.", type: CNAME }] }
        : { status: 0, answers: [{ data: "257 3 8 AwEAAc...", type: DNSKEY }] };

    expect(await checkDnssec("www.nasa.gov")).toEqual([]);
  });

  it("still reports a zone that is genuinely unsigned", async () => {
    const vulns = await checkDnssec("www.example.com");
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.name).toMatch(/DNSSEC/i);
    expect(vulns[0]!.evidence).toMatch(/example\.com/);
  });
});
