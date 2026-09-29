import { describe, it, expect } from "vitest";
import { runWithScanHttp } from "./http";
import { actableEndpoints, pathLeaf, type EndpointRef } from "./actingEndpoints";

const inScan = <T>(fn: () => T): T => {
  let out!: T;
  void runWithScanHttp({ targetUrl: "https://app.acme.com/" }, async () => { out = fn(); });
  return out;
};
const ANY = () => true;

describe("pathLeaf", () => {
  it.each([
    ["https://app.acme.com/api/chat", "chat", "api"],
    ["https://app.acme.com/api/chat_stream", "chatstream", "api"],
    ["https://app.acme.com/api/chatCompletion/", "chatcompletion", "api"],
    ["https://app.acme.com/v1/chat/completions?x=1", "completions", "chat"],
    ["https://app.acme.com/", "", ""],
  ])("%s -> leaf %j, parent %j", (url, leaf, parent) => {
    expect(pathLeaf(url)).toEqual({ leaf, parent });
  });

  it("reads the PATH only: a chat-, ask- or claim- host name says nothing about the route", () => {
    expect(pathLeaf("https://chat.acme.com/api/users").leaf).toBe("users");
    expect(pathLeaf("https://promo.acme.com/api/account/delete").leaf).toBe("delete");
  });
});

describe("actableEndpoints: what an active probe may POST to", () => {
  const list = (eps: Array<string | EndpointRef>): string[] =>
    inScan(() => actableEndpoints(eps, ANY).map((e) => e.url));

  it("keeps an in-scope, concrete, non-destructive URL", () => {
    expect(list(["https://app.acme.com/api/chat"])).toEqual(["https://app.acme.com/api/chat"]);
  });

  it("keeps a subdomain of the target, which the scan's scope includes", () => {
    expect(list(["https://v2.app.acme.com/chat"])).toEqual(["https://v2.app.acme.com/chat"]);
  });

  it("drops a third-party host, however chat-shaped: active probes go to the target only", () => {
    // A spec's servers[0].url is used verbatim, so https://api.openai.com/v1/chat/completions can
    // arrive here from the target's own /openapi.json.
    expect(list(["https://api.openai.com/v1/chat/completions", "https://evil.example/api/chat"])).toEqual([]);
  });

  it("fails closed with no scan context: there is no target to be in scope of", () => {
    expect(actableEndpoints(["https://app.acme.com/api/chat"], ANY)).toEqual([]);
  });

  it("drops URLs that would act rather than show", () => {
    expect(list(["https://app.acme.com/api/chat/clear", "https://app.acme.com/api/coupon/remove", "https://app.acme.com/api/claim/delete"])).toEqual([]);
  });

  it("drops a URL that still holds a placeholder, which would be POSTed literally", () => {
    expect(list(["https://app.acme.com/api/coupons/{id}/redeem", "https://app.acme.com/api/chat/${id}"])).toEqual([]);
  });

  it("honours a declared method: a spec's GET or DELETE is not a POST target", () => {
    expect(list([
      { url: "https://app.acme.com/api/chat", method: "GET", source: "spec" },
      { url: "https://app.acme.com/api/ask", method: "DELETE", source: "spec" },
      { url: "https://app.acme.com/api/prompt", method: "POST", source: "spec" },
    ])).toEqual(["https://app.acme.com/api/prompt"]);
  });

  it("does not trust a bundle endpoint's method, which is only a guess", () => {
    expect(list([{ url: "https://app.acme.com/api/chat", method: "GET", source: "bundle" }])).toEqual(["https://app.acme.com/api/chat"]);
  });

  it("honours a runtime-observed method", () => {
    expect(list([{ url: "https://app.acme.com/api/chat", method: "GET", source: "runtime" }])).toEqual([]);
  });

  it("applies the caller's own matcher to the path", () => {
    const only = (url: string) => url.endsWith("/ask");
    expect(inScan(() => actableEndpoints(["https://app.acme.com/api/chat", "https://app.acme.com/api/ask"], only).map((e) => e.url)))
      .toEqual(["https://app.acme.com/api/ask"]);
  });

  it("removes duplicates and skips unparseable entries", () => {
    expect(list(["https://app.acme.com/api/chat", "https://app.acme.com/api/chat", "not a url", ""])).toEqual(["https://app.acme.com/api/chat"]);
  });
});
