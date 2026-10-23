import { useDohStub, txt } from "./dohStub.testkit";
import { describe, it, expect } from "vitest";
import { checkDmarc, checkDkim, checkDnsSecurity } from "./dnsChecks.js";
import { registrableDomain } from "./registrableDomain.js";
import { countSpfLookups } from "./emailAuthParse.js";

// The resolver is a real DNS-over-HTTPS server on loopback (lib/dohStub.testkit.ts); the zone is set in each test.
const doh = await useDohStub();

describe("SPF lookup counting", () => {
  it("counts whole lookup terms only", () => {
    expect(countSpfLookups("v=spf1 a mx:mail.example.com include:x.net ~a:foo.example redirect=_spf.example.com")).toBe(5);
    expect(countSpfLookups("v=spf1 ip4:1.2.3.4 ip6:fe80::a:1 -all")).toBe(0);
  });
});

describe("registrableDomain", () => {
  it("keeps the organisation label under common multi-label suffixes", () => {
    expect(registrableDomain("www.example.co.uk")).toBe("example.co.uk");
    expect(registrableDomain("a.b.example.com.au")).toBe("example.com.au");
    expect(registrableDomain("shop.example.co.jp")).toBe("example.co.jp");
    expect(registrableDomain("www.example.com")).toBe("example.com");
    expect(registrableDomain("example.com")).toBe("example.com");
  });
});

describe("DKIM is asked about the registrable domain", () => {
  it("probes selectors under example.co.uk, not co.uk, for www.example.co.uk", async () => {
    doh.rule = (name, type) => (type === "TXT" && name.startsWith("_dmarc.") ? { status: 0, answers: txt("v=DMARC1; p=none") } : undefined);
    const vulns = await checkDnsSecurity("https://www.example.co.uk/");
    const dkimNames = doh.asked.filter((q) => q.includes("_domainkey."));
    expect(dkimNames.length).toBeGreaterThan(0);
    expect(dkimNames.every((q) => q.includes("_domainkey.example.co.uk "))).toBe(true);
    const dkim = vulns.find((v) => /DKIM/.test(v.name));
    expect(dkim?.description).toMatch(/for example\.co\.uk/);
  });

  it("hedges a no-DKIM result: guessed selectors are weak evidence", async () => {
    const [v] = await checkDkim("example.com");
    expect(v!.name).toMatch(/common selectors/i);
    expect(v!.description).toMatch(/custom selector/i);
    expect(v!.confidence).toBeLessThan(60);
  });
});

describe("DMARC sp= on an inherited record", () => {
  const record = "v=DMARC1; p=none; sp=reject; rua=mailto:r@example.com";
  const publish = () => doh.set("_dmarc.example.com", "TXT", txt(record));

  it("does not report p=none for a subdomain that inherits sp=reject", async () => {
    publish();
    expect(await checkDmarc("app.example.com")).toEqual([]);
  });

  it("still reports p=none for the domain that publishes the record", async () => {
    publish();
    const vulns = await checkDmarc("example.com");
    expect(vulns.some((v) => /policy set to none/i.test(v.name))).toBe(true);
  });
});
