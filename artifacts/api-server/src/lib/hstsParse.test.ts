import { describe, it, expect } from "vitest";
import { parseHsts } from "./hstsParse";
import { transportFindings } from "./scannerTransportChecks";
import { spfAllQualifier } from "./dnsChecksMail";

describe("parseHsts (RFC 6797 section 6.1)", () => {
  it("reads a plain header", () => {
    expect(parseHsts("max-age=31536000; includeSubDomains; preload")).toEqual({ maxAge: 31536000, includeSubDomains: true, preload: true });
  });
  it("reads a quoted max-age, which the RFC allows", () => {
    expect(parseHsts('max-age="31536000"').maxAge).toBe(31536000);
  });
  it("is case-insensitive about names and spacing", () => {
    expect(parseHsts("Max-Age = 600 ;INCLUDESUBDOMAINS")).toMatchObject({ maxAge: 600, includeSubDomains: true });
  });
  it("counts only the first of a repeated directive", () => {
    expect(parseHsts("max-age=100; max-age=999999").maxAge).toBe(100);
  });
  it("has no usable max-age when it is missing or not a number", () => {
    expect(parseHsts("includeSubDomains").maxAge).toBeNull();
    expect(parseHsts("max-age=abc").maxAge).toBeNull();
    expect(parseHsts("").maxAge).toBeNull();
  });
});

describe("the HSTS findings", () => {
  const run = (hsts: string) => transportFindings({ finalUrl: "https://example.test/", rawHeaders: { "strict-transport-security": hsts }, isHttps: true } as never);
  const names = async (hsts: string) => (await run(hsts)).map((v) => v.name);

  it("a quoted long max-age is healthy, not 'too short'", async () => {
    expect(await names('max-age="31536000"; includeSubDomains')).toEqual([]);
  });
  it("max-age=0 is a withdrawn policy, not a short one", async () => {
    expect(await names("max-age=0")).toEqual(["HSTS Policy Is Being Removed (max-age=0)"]);
  });
  it("a header with no max-age is ignored by browsers, and says so", async () => {
    expect(await names("includeSubDomains; preload")).toEqual(["HSTS Header Has No Usable max-age (Ignored by Browsers)"]);
  });
  it("clean twin: a genuinely short max-age is still 'too short'", async () => {
    expect(await names("max-age=86400")).toEqual(["HSTS max-age Too Short"]);
  });
});

describe("spfAllQualifier (RFC 7208 section 4.6.2)", () => {
  it.each([
    ["v=spf1 include:_spf.google.com +all", "+"],
    ["v=spf1 a mx all", "+"], // a bare all means +all
    ["v=spf1 a mx ALL", "+"],
    ["v=spf1 include:_spf.google.com ~all", "~"],
    ["v=spf1 mx -all", "-"],
    ["v=spf1 ?all", "?"],
  ])("%s -> %s", (record, expected) => expect(spfAllQualifier(record)).toBe(expected));

  it("does not read text inside another term as the all mechanism", () => {
    expect(spfAllQualifier("v=spf1 include:mail+all.example.test -all")).toBe("-");
    expect(spfAllQualifier("v=spf1 include:marketing-all.example.test ~all")).toBe("~");
  });
  it("is null when there is no all mechanism (a redirect, say)", () => {
    expect(spfAllQualifier("v=spf1 redirect=_spf.example.test")).toBeNull();
  });
});
