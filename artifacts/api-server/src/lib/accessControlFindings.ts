/**
 * A01 access-control probe: the findings it reports.
 *
 * Split out of accessControlProbe.ts. That module decides which URLs were hit
 * and by which leg of the three-way comparison; this one turns those lists
 * into the report entries, so the wording, severities and CWE/CVSS/WSTG ids
 * sit apart from the request logic.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/** The URLs each kind of finding was raised for. */
export interface AccessControlHits {
  /** Both accounts read a crawled record; the anonymous request was refused. */
  idorHits: string[];
  /** Readable with no session at all. */
  anonHits: string[];
  /** Reached only by editing the identifier of a crawled record. */
  enumeratedHits: string[];
}

export function buildAccessControlFindings(
  { idorHits, anonHits, enumeratedHits }: AccessControlHits,
  secondaryAutoCreated?: boolean,
): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];
  const autoAccountNote = secondaryAutoCreated
    ? "\n\nThe second account was created automatically by this scan through your public signup form. " +
      "Nothing confirms it belongs to a different organisation or tenant than the first: if your signup places " +
      "every new user in one shared workspace, identical content is expected and this is not a leak. If the " +
      "two accounts should be isolated from each other, it is one."
    : "";

  if (idorHits.length > 0) {
    findings.push(
      vuln({
        name: "Broken Object-Level Authorisation (IDOR)",
        severity: "critical",
        category: "Broken Access Control",
        description:
          `A second, unrelated account was served the same records as the first at ${idorHits.length} ` +
          `URL${idorHits.length > 1 ? "s" : ""}. The application checks that someone is signed in, but not ` +
          `that they own the record they asked for — so any user can read another user's data by changing ` +
          `the identifier in the URL. This is the most commonly exploited web vulnerability class, and it ` +
          `requires no tooling: a customer can trip over it by editing their address bar.`,
        evidence:
          `Requested as two separate accounts and as an anonymous visitor.\n` +
          `Both accounts received matching content; the anonymous request was refused.\n\n` +
          idorHits.map((u) => `  ${u}`).join("\n") +
          autoAccountNote,
        solution:
          "Authorise the object, not just the session. On every request that loads a record by id, confirm " +
          "the record belongs to the caller — a WHERE clause scoped to the current user id, or an explicit " +
          "ownership check before returning it. Do not rely on identifiers being hard to guess; sequential " +
          "ids simply make it faster. Apply the same check to every verb, including update and delete.",
        cweId: "CWE-639",
        cvssScore: 8.1,
        wstgId: "WSTG-ATHZ-04",
        confidence: secondaryAutoCreated ? 70 : 90,
      }),
    );
  }

  if (enumeratedHits.length > 0) {
    findings.push(
      vuln({
        name: "Records Enumerable by Editing the Identifier",
        severity: "critical",
        category: "Broken Access Control",
        description:
          `Changing the identifier in the URL reached ${enumeratedHits.length} record` +
          `${enumeratedHits.length > 1 ? "s" : ""} that neither account was ever linked to, and both ` +
          `accounts were served the same content. Two separate accounts cannot both own one record, so ` +
          `at least one of them is reading data that is not theirs — and because the identifiers are ` +
          `sequential, an attacker does not need to guess: they can walk the whole table by counting. ` +
          `This is how bulk data breaches usually happen, rather than through any single clever exploit.`,
        evidence:
          `Reached by altering the identifier of a record the scan was legitimately shown.\n` +
          `Both accounts received matching content; the anonymous request was refused.\n\n` +
          enumeratedHits.map((u) => `  ${u}`).join("\n") +
          autoAccountNote,
        solution:
          "Two fixes, and you want both. First, authorise the object: confirm the record belongs to the " +
          "caller before returning it — a WHERE clause scoped to the current user id. Second, stop using " +
          "sequential integers as public identifiers; a UUID does not prevent an authorisation bug but it " +
          "does stop an attacker enumerating every record once they find one.",
        cweId: "CWE-639",
        cvssScore: 8.6,
        wstgId: "WSTG-ATHZ-04",
        // A shade below the direct case: two accounts in one organisation may
        // legitimately share a record, which looks identical from outside.
        confidence: secondaryAutoCreated ? 60 : 80,
      }),
    );
  }

  if (anonHits.length > 0) {
    findings.push(
      vuln({
        name: "Records Readable Without Signing In",
        severity: "high",
        category: "Broken Access Control",
        description:
          `${anonHits.length} URL${anonHits.length > 1 ? "s that name specific records were" : " that names a specific record was"} ` +
          `served in full to a request carrying no session at all, matching what the signed-in account saw. ` +
          `If these records are meant to be private, they are currently public to anyone who knows or guesses the address.`,
        evidence:
          `Identical content returned with and without a session:\n\n` +
          anonHits.map((u) => `  ${u}`).join("\n"),
        solution:
          "Require an authenticated session on any route that returns a specific record, and authorise the " +
          "record against that session. If these particular pages are meant to be public, no change is needed — " +
          "but confirm that deliberately rather than by default.",
        cweId: "CWE-306",
        cvssScore: 7.5,
        wstgId: "WSTG-ATHZ-02",
        confidence: 75,
      }),
    );
  }

  return findings;
}
