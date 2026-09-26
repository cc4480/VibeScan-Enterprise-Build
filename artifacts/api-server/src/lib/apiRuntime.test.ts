import { describe, it, expect } from "vitest";
import { endpointsFromRuntime, jsonBodyKeys, type ObservedRequest } from "./apiRuntime";

const ORIGIN = "https://app.example.com";
const get = (url: string): ObservedRequest => ({ method: "GET", url });

describe("endpointsFromRuntime", () => {
  it("turns the page's own API calls into endpoints with their parameter names", () => {
    const out = endpointsFromRuntime([get(`${ORIGIN}/api/notes?owner=me&page=2`)], ORIGIN);
    expect(out).toEqual([{
      url: `${ORIGIN}/api/notes`, method: "GET", source: "runtime",
      params: [{ name: "owner", location: "query" }, { name: "page", location: "query" }],
    }]);
  });

  it("never carries a query value into an endpoint, so a token in a URL stays out", () => {
    const out = endpointsFromRuntime([get(`${ORIGIN}/api/me?access_token=SECRETVALUE123`)], ORIGIN);
    expect(JSON.stringify(out)).not.toContain("SECRETVALUE123");
  });

  it("keeps the names of a JSON body's keys, not their values", () => {
    const out = endpointsFromRuntime([{ method: "post", url: `${ORIGIN}/api/search`, bodyKeys: ["term", "limit"] }], ORIGIN);
    expect(out[0]!.method).toBe("POST");
    expect(out[0]!.params).toEqual([{ name: "term", location: "body" }, { name: "limit", location: "body" }]);
  });

  it("counts /users/42 and /users/97 as one endpoint and merges what was seen of it", () => {
    const out = endpointsFromRuntime([get(`${ORIGIN}/api/users/42?fields=name`), get(`${ORIGIN}/api/users/97?expand=team`)], ORIGIN);
    expect(out).toHaveLength(1);
    expect(out[0]!.params.map((p) => p.name).sort()).toEqual(["expand", "fields"]);
  });

  it("treats the same path with a different method as a different endpoint", () => {
    const out = endpointsFromRuntime([get(`${ORIGIN}/api/items`), { method: "POST", url: `${ORIGIN}/api/items` }], ORIGIN);
    expect(out.map((e) => e.method).sort()).toEqual(["GET", "POST"]);
  });

  it("ignores third parties, other schemes, garbage and anything that looks like an action", () => {
    const out = endpointsFromRuntime([
      get("https://www.google-analytics.com/collect?v=1"),
      get("https://api.stripe.com/v1/charges"),
      get("wss://app.example.com/socket"),
      get("not a url"),
      { method: "POST", url: `${ORIGIN}/api/account/delete` },
      { method: "POST", url: `${ORIGIN}/api/logout` },
    ], ORIGIN);
    expect(out).toEqual([]);
  });

  it("accepts the site's own sibling hosts, like an api subdomain", () => {
    expect(endpointsFromRuntime([get("https://api.example.com/v1/list")], ORIGIN)).toHaveLength(1);
  });

  it("caps how many requests it will consider", () => {
    const many = Array.from({ length: 500 }, (_, i) => get(`${ORIGIN}/api/thing${i}`));
    expect(endpointsFromRuntime(many, ORIGIN).length).toBeLessThanOrEqual(80);
  });

  it("returns nothing for nothing", () => {
    expect(endpointsFromRuntime([], ORIGIN)).toEqual([]);
    expect(endpointsFromRuntime([get(`${ORIGIN}/x`)], "nonsense")).toEqual([]);
  });
});

describe("jsonBodyKeys", () => {
  it("reads the top-level key names of a JSON object", () => {
    expect(jsonBodyKeys('{"email":"a@b.c","password":"hunter2"}')).toEqual(["email", "password"]);
  });
  it("returns nothing for arrays, form data, empty and invalid bodies", () => {
    for (const body of ["[1,2]", "a=1&b=2", "", null, undefined, "{oops"]) expect(jsonBodyKeys(body)).toEqual([]);
  });
});
