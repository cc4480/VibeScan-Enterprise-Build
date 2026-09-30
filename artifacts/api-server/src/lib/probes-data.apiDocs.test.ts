import { describe, it, expect } from "vitest";
import { SENSITIVE_PATHS } from "./probes-data.js";

const docs = SENSITIVE_PATHS.filter((p) => /^\/api(?:\/v\d)?\/swagger\.json$/.test(p.path));
const SPEC = JSON.stringify({ openapi: "3.0.1", info: { title: "t", version: "1" }, paths: { "/u": {} } });

describe("API doc variants in the root path probes", () => {
  it("covers the three variants", () => expect(docs.map((d) => d.path).sort()).toEqual(["/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json"]));

  it.each(docs.map((d) => [d.path, d] as const))("%s is info severity, like apiDocsProbe", (_p, d) =>
    expect(d.severity).toBe("info"));

  it.each(docs.map((d) => [d.path, d] as const))("%s accepts a real spec", (_p, d) =>
    expect(d.validate(SPEC, "application/json")).toBe(true));

  it.each(docs.map((d) => [d.path, d] as const))("%s rejects a body that merely says swagger/openapi", (_p, d) => {
    expect(d.validate('{"swagger":"see docs","message":"openapi coming soon"}', "application/json")).toBe(false);
    expect(d.validate('{"error":"not found","hint":"\\"openapi\\" endpoint moved"}', "application/json")).toBe(false);
    expect(d.validate("<html>swagger openapi</html>", "text/html")).toBe(false);
  });
});
