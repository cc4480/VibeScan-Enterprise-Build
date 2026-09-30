/**
 * The two findings the GitHub source scan raises about configuration files and about its own
 * coverage. Split out of githubSourceProbe.ts, which decides what to read.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import type { GithubRepoRef } from "./githubSourceProbe";
import { MAX_FILES } from "./githubCandidates";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

export function configFinding(ref: GithubRepoRef, path: string, hit: { key: string; redacted: string; line: number; inExampleFile: boolean }): ScanVulnerability {
  return vuln({
    name: "Hardcoded Secret in Config File (in source repository)",
    // An example file's value is more often a template that slipped through than a live secret.
    severity: hit.inExampleFile ? "medium" : "high",
    category: "Exposed Secrets / Credentials",
    description:
      `A value that looks like a real secret is committed in ${path} of ${ref.owner}/${ref.repo}, under the key ${hit.key}. ` +
      // The report merges findings of one name into one entry, so a second hit's file and key are in the evidence.
      `If more than one file or key is affected, each is listed in the evidence. ` +
      `Anyone who can read the repository can read it, and it stays in the history after it is deleted from the file. ` +
      `This is a source-code finding, not something read from the live site.`,
    evidence: `Repository: ${ref.owner}/${ref.repo}\nFile: ${path} (line ${hit.line})\nKey: ${hit.key}\nValue (redacted): ${hit.redacted}`,
    solution:
      "Rotate the secret now: removing it from the file does not remove it from Git history. Keep real values out of the repository " +
      "(environment variables, a secrets manager) and commit only a template with placeholder values.",
    cweId: "CWE-798",
    cvssScore: hit.inExampleFile ? 5.3 : 7.5,
    wstgId: "WSTG-CONF-04",
  });
}

/** Says so, in the report, when the scan covered only part of the repository. Not a credential finding. */
export function partialNote(
  ref: GithubRepoRef,
  n: { filesRead: number; attempted: number; skipped: number; truncated: boolean },
): ScanVulnerability {
  const lines = [
    `Repository: ${ref.owner}/${ref.repo}`,
    `Files read: ${n.filesRead} of ${n.attempted} chosen`,
    ...(n.skipped > 0 ? [`Not read because of the ${MAX_FILES}-file limit: ${n.skipped}`] : []),
    ...(n.truncated ? ["GitHub truncated the repository's file list, so files beyond it were never seen"] : []),
    ...(n.filesRead < n.attempted ? [`${n.attempted - n.filesRead} chosen file(s) could not be downloaded`] : []),
  ];
  return vuln({
    name: "GitHub source scan covered only part of the repository",
    severity: "info",
    category: "Scan Coverage",
    description:
      "The source-code scan read a fixed, prioritised list of configuration files and could not read all of them. " +
      "Nothing found in the files it did read is a statement about the rest, so this result should not be read as a clean scan of the repository.",
    evidence: lines.join("\n"),
    solution: "Re-run the scan, or check the files it did not reach by hand.",
    confidence: 100,
  });
}
