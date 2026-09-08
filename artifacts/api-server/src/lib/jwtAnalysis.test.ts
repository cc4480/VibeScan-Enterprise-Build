import { describe, it, expect } from "vitest";
import { analyzeJwts } from "./jwtAnalysis.js";

function jwt(header: object, payload: object, sig = "sig123456"): string {
  const b64 = (o: object) =>
    Buffer.from(JSON.stringify(o)).toString("base64url").replace(/=+$/, "");
  return `${b64(header)}.${b64(payload)}.${sig}`;
}

describe("analyzeJwts — infrastructure tokens are not credentials", () => {
  it("does NOT flag expiry on Netlify's deploy token", async () => {
    // The real token Netlify injects into every site it hosts. It names a
    // build, not a person — found on mistral.ai, where it produced two Highs
    // ("no expiry" + "HS256 without expiry") on a value that grants nothing.
    const netlify = jwt(
      { alg: "HS256", typ: "JWT" },
      {
        site_id: "4de7bfd2-dc74-4fc2-af90-4f9a8f1409c1",
        account_id: "68f0eaa558eced49f8b16b01",
        deploy_id: "6a9eba54cf6a3b0008e6b9be",
        issuer: "nfserver",
      },
    );
    const findings = await analyzeJwts({}, `<html><body>${netlify}</body></html>`);
    expect(findings.map((f) => f.name)).toEqual([]);
  });

  it("STILL flags a real session token with no expiry", async () => {
    const session = jwt({ alg: "HS256", typ: "JWT" }, { sub: "user_8471", email: "a@b.com" });
    const findings = await analyzeJwts({}, `<html><body>${session}</body></html>`);
    const names = findings.map((f) => f.name).join(" | ");
    expect(names).toMatch(/No Expiry/i);
    expect(names).toMatch(/HS256 Without Expiry/i);
  });

  it("STILL flags an authorization token carrying only a role/scope", async () => {
    const svc = jwt({ alg: "HS256", typ: "JWT" }, { role: "admin", scope: "read:all" });
    const findings = await analyzeJwts({}, `<html>${svc}</html>`);
    expect(findings.map((f) => f.name).join(" ")).toMatch(/No Expiry/i);
  });

  it("STILL flags alg:none regardless of token purpose — broken crypto is broken", async () => {
    const none = jwt({ alg: "none", typ: "JWT" }, { site_id: "x", deploy_id: "y" }, "");
    const findings = await analyzeJwts({}, `<html>${none}</html>`);
    expect(findings.map((f) => f.name).join(" ")).toMatch(/alg:none/i);
  });
});
