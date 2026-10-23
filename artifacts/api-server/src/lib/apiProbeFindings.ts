import { vuln, RATE_LIMIT_BURST } from "./apiProbeHelpers";
import type { ApiProbeHits } from "./apiProbeEndpoint";
import type { ScanVulnerability } from "./scanner";

/** Turns what the API probes collected into findings. */
export function buildApiFindings(hits: ApiProbeHits): ScanVulnerability[] {
  const { unauthenticated, injectable, overExposed, unratelimited, crossAccount, massAssignable, unauthorizedWrites } = hits;
const findings: ScanVulnerability[] = [];

if (unauthenticated.length > 0) {
  findings.push(
    vuln({
      name: "API Endpoints Served Without Authentication",
      severity: "high",
      category: "Broken Access Control",
      description:
        `${unauthenticated.length} API endpoint${unauthenticated.length > 1 ? "s" : ""} returned data to a ` +
        `request carrying no session at all, matching what the signed-in session received. On a ` +
        `single-page app this is where data actually leaks: the endpoints are invisible in the HTML, so ` +
        `they are easy to ship without the authentication check the pages around them have. Anyone who ` +
        `reads your JavaScript bundle can find and call them.`,
      evidence:
        `Requested with the scan's session and with none, and compared:\n\n` +
        unauthenticated.map((e) => `  ${e}`).join("\n") +
        `\n\nIf any of these are meant to be public, no change is needed — but confirm that deliberately.`,
      solution:
        "Apply the authentication check at the router or middleware level so every endpoint is protected " +
        "by default and public ones are the explicit exception. Checking inside each handler means a new " +
        "handler is unprotected until somebody remembers, which is how these appear.",
      cweId: "CWE-306",
      cvssScore: 7.5,
      wstgId: "WSTG-ATHZ-01",
      confidence: 85,
    }),
  );
}

if (crossAccount.length > 0) {
  findings.push(
    vuln({
      name: "API Records Readable by Another Account",
      severity: "critical",
      category: "Broken Access Control",
      description:
        `A second, unrelated account received byte-identical data from ${crossAccount.length} API ` +
        `endpoint${crossAccount.length > 1 ? "s" : ""} that name a specific record. The API confirms someone ` +
        `is signed in but not that the record is theirs, so any user can read another user's data by ` +
        `changing the identifier. Two separate accounts cannot both own one record.`,
      evidence:
        `Requested as two separate accounts; both received identical responses:

` +
        crossAccount.map((e) => `  ${e}`).join("\n") +
        `

If these two accounts share an organisation, sharing the record may be intended.`,
      solution:
        "Scope the query to the caller: load the record with a WHERE clause bound to the current user or " +
        "tenant id, rather than fetching by id and returning it. Apply it in one place — a repository " +
        "layer or middleware — so a new endpoint inherits the check instead of needing to remember it.",
      cweId: "CWE-639",
      cvssScore: 8.1,
      wstgId: "WSTG-ATHZ-04",
      confidence: 85,
    }),
  );
}

if (unauthorizedWrites.length > 0) {
  findings.push(
    vuln({
      name: "Write Endpoints Reachable Without Authentication",
      severity: "critical",
      category: "Broken Access Control",
      description:
        `${unauthorizedWrites.length} write endpoint${unauthorizedWrites.length > 1 ? "s" : ""} processed an ` +
        `unauthenticated request instead of refusing it: the handler ran (it accepted the request, or ` +
        `got as far as validating it) with no session at all. Aimed at a real identifier instead of a ` +
        `nonexistent one, the same request may have modified or deleted the record.`,
      evidence:
        `Sent with no session, against an identifier chosen so nothing could exist at it, so nothing was ` +
        `modified:

` +
        unauthorizedWrites.map((e) => `  ${e}`).join("\n") +
        `

A protected endpoint answers 401 or 403 here. A 404 or 405 would have proved nothing and was not counted.`,
      solution:
        "Check authentication and authorisation before the handler does any work, in middleware rather than " +
        "inside each handler, so an unauthenticated write is refused with 401 or 403 whether or not the " +
        "record exists.",
      cweId: "CWE-862",
      cvssScore: 9.1,
      wstgId: "WSTG-ATHZ-02",
      confidence: 75,
    }),
  );
}

if (overExposed.length > 0) {
  const allFields = [...new Set(overExposed.flatMap((e) => e.fields))];
  findings.push(
    vuln({
      name: "Sensitive Fields Returned by the API",
      severity: "high",
      category: "Information Disclosure",
      description:
        `API responses include field${allFields.length > 1 ? "s" : ""} named ${allFields.join(", ")}. This is ` +
        `the signature of an endpoint returning a whole database row and letting the front end pick what to ` +
        `display: the values still crossed the network, still sit in the browser's memory, and are visible ` +
        `to anyone who opens the network tab. Hiding a field in the interface does not remove it from the ` +
        `response.`,
      evidence: overExposed.map((e) => `  ${e.endpoint}   ${e.fields.join(", ")}`).join("\n"),
      solution:
        "Serialise responses through an explicit shape that names the fields to include, rather than " +
        "returning the model and removing fields you remember to remove. A field added to the table later " +
        "then stays out of the API by default instead of leaking on the next deploy.",
      cweId: "CWE-213",
      cvssScore: 7.5,
      wstgId: "WSTG-ATHZ-04",
      confidence: 80,
    }),
  );
}

if (massAssignable.length > 0) {
  findings.push(
    vuln({
      name: "Privilege Fields Accepted in Request Bodies",
      severity: "medium",
      category: "Broken Access Control",
      description:
        `The API contract declares that these endpoints accept fields that decide privilege or ownership. ` +
        `If any is bound straight onto the stored record, a caller can grant themselves a role, change a ` +
        `plan, or reassign a record to another owner simply by including the field. This is read from the ` +
        `declared schema, not confirmed by sending one — testing it for real would mean granting somebody ` +
        `a role.`,
      evidence:
        massAssignable.map((e) => `  ${e.endpoint}   ${e.fields.join(", ")}`).join("\n") +
        `

Verify by hand whether each field is actually bound to the model.`,
      solution:
        "Bind request bodies to an explicit allowlist of writable fields per endpoint. Never pass a parsed " +
        "body into a model constructor or update call wholesale — that is what turns an extra JSON key into " +
        "a privilege escalation.",
      cweId: "CWE-915",
      cvssScore: 6.5,
      wstgId: "WSTG-BUSL-01",
      confidence: 55,
    }),
  );
}

if (unratelimited.length > 0) {
  findings.push(
    vuln({
      name: "No Rate Limiting Observed on Sensitive API Endpoints",
      severity: "info",
      category: "Security Misconfiguration",
      description:
        `${unratelimited.length} sign-in, password-reset or code-verification endpoint${unratelimited.length > 1 ? "s" : ""} ` +
        `answered a burst of ${RATE_LIMIT_BURST} rapid requests without once answering 429. That is a ` +
        `short burst: a limiter with a higher threshold, one keyed on the account name rather than the ` +
        `address, or one at an edge that does not announce itself would not have engaged, so this is a ` +
        `prompt to check, not proof that no limit exists. Without one, credential and code guessing is cheap.`,
      evidence:
        `${RATE_LIMIT_BURST} requests in immediate succession, none answered with 429:

` +
        unratelimited.map((e) => `  ${e}`).join("\n"),
      solution:
        "Rate limit at the edge — reverse proxy, CDN or API gateway — so it applies to every route by " +
        "default. Apply a tighter limit to authentication and anything that reads by identifier, which are " +
        "the endpoints worth attacking in bulk.",
      cweId: "CWE-770",
      cvssScore: 0,
      wstgId: "WSTG-ATHN-04",
      confidence: 50,
    }),
  );
}

if (injectable.length > 0) {
  findings.push(
    vuln({
      name: "SQL Injection in API Parameters",
      severity: "critical",
      category: "Injection",
      description:
        `A single quote sent to ${injectable.length} API parameter${injectable.length > 1 ? "s" : ""} produced a ` +
        `database error that the same request without the quote did not. The value is reaching the SQL ` +
        `parser, which means an attacker can alter the query — reading any table, and often writing to ` +
        `them. These parameters are declared by the API rather than exposed in a form, so no amount of ` +
        `testing through the user interface would have found them.`,
      evidence:
        `Baseline and injected requests compared per parameter; the error signature was absent from the baseline.\n\n` +
        injectable.map((i) => `  ${i.endpoint}   ${i.param} (${i.where})`).join("\n"),
      solution:
        "Use parameterised queries or a query builder that binds values — never string concatenation, and " +
        "never an allowlist of 'dangerous characters', which is repeatedly defeated. If an ORM is already " +
        "in use, find the raw query that bypassed it. Fix every listed parameter: they are likely the same " +
        "handler pattern repeated.",
      cweId: "CWE-89",
      cvssScore: 9.8,
      wstgId: "WSTG-INPV-05",
      confidence: 90,
    }),
  );
}

return findings;
}
