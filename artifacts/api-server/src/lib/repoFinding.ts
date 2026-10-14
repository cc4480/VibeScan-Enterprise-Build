import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

/** A repository being read: where it is, and which branch. */
export interface RepoRef { owner: string; repo: string; branch?: string }

/** One file of the repository, as text. */
export interface RepoFile { path: string; content: string }

export interface RepoFindingInput {
  ref: RepoRef;
  /** The file (or files) the finding is about. */
  path: string;
  name: string;
  severity: ScanVulnerability["severity"];
  category: string;
  description: string;
  /** Extra evidence lines after the repository and file. Never a raw secret. */
  detail?: string;
  solution: string;
  cweId: string | null;
  cvssScore: number;
  confidence?: number;
  wstgId?: string;
}

/**
 * Every repository finding names the repository and the file, says it was read from source (so it is not mistaken
 * for something observed on the live site), and carries a confidence: a static read of source is weaker evidence
 * than a request that was answered.
 */
export function repoFinding(i: RepoFindingInput): ScanVulnerability {
  return {
    id: randomUUID(),
    name: i.name,
    severity: i.severity,
    category: i.category,
    description: `${i.description} This was read from the source repository ${i.ref.owner}/${i.ref.repo}, not observed on the live site.`,
    evidence: `Repository: ${i.ref.owner}/${i.ref.repo}\nFile: ${i.path}${i.detail ? `\n${i.detail}` : ""}`,
    solution: i.solution,
    cweId: i.cweId,
    cvssScore: i.cvssScore,
    confidence: i.confidence ?? 70,
    ...(i.wstgId ? { wstgId: i.wstgId } : {}),
  } as ScanVulnerability;
}

/** A test, mock, example or documentation file: a secret-shaped value there is far more often a fake than a leak. */
export const isTestOrExamplePath = (p: string) =>
  /(?:^|\/)(?:__tests__|__mocks__|tests?|spec|e2e|cypress|mocks?|examples?|samples?|docs?|demos?|playgrounds?|sandbox(?:es)?|storybook|\.storybook)\//i.test(p) ||
  // Test files named by language convention: Go, Python, Ruby, JVM and .NET.
  /(?:_test\.(?:go|py|rb|exs?|rs)|_spec\.rb|(?:Test|Tests|IT|Spec)\.(?:java|kt|kts|cs|scala|swift)|\.(?:stories|story)\.[a-z0-9]+)$/.test(p) ||
  /\.(?:test|spec)\.[a-z0-9]+$/i.test(p) ||
  // Prose: a changelog or a README mentions addresses and keys as examples.
  /\.(?:md|mdx|markdown|rst|adoc)$/i.test(p) ||
  /(?:^|\/)(?:test|spec)[-_.][^/]*$/i.test(p);

/** The code around a match calls it a fake: FORGED_TOKEN, dummyKey, a fixture, an example, a probe. */
export const namesItselfFake = (context: string): boolean => /(?:forged|fake|dummy|bogus|mock|fixture|placeholder|example|sample|probe)/i.test(context);

/**
 * The same finding, shown as information under its own name. Its own name, so that it is never merged into (and never
 * hides, or is hidden by) a finding of the same kind in a file that ships.
 */
export function asTestFileFinding(v: ScanVulnerability, why: "test-file" | "named-fake" | "dev-default" = "test-file"): ScanVulnerability {
  const suffix = why === "test-file" ? " (in a test or example file)" : why === "dev-default" ? " (looks like a development default)" : " (a value that looks deliberately fake)";
  return {
    ...v,
    name: v.name.includes(" (in source repository)") ? v.name.replace(" (in source repository)", suffix) : `${v.name}${suffix}`,
    severity: "info",
    cvssScore: 0,
    confidence: 40,
    description: `${v.description} ${why === "test-file" ? "It is in a test, mock, example or documentation file, where a fake value is the usual reason" : why === "dev-default" ? "It is a plain lowercase word in a compose, CI or development file: the throwaway password of a local or test database" : "The code around it names it as fake (forged, dummy, fixture, example, probe), where a fake value is the usual reason"}, so it is shown as information. If it is more than a sample (a real credential, or the setup of a live service), treat it as a real finding.`,
  } as ScanVulnerability;
}

/**
 * Files under a directory the project does not own (dependencies, build output, fixtures).
 *
 * Includes deliberately vulnerable test targets (test-targets/, vuln-fixtures/, vulnerable-app/): a scanner
 * or security tool keeps sample apps with RLS switched off on purpose, and reporting those as the project's
 * own HIGH findings is a false alarm about code that never ships. Env files are still read wherever they sit
 * (see repoScan.ts), because a real key committed into a fixture is still a real leak.
 */
export const NOT_THE_PROJECTS_OWN = /(?:^|\/)(?:node_modules|vendor|third_party|dist|build|out|coverage|\.next|\.git|\.turbo|__tests__|__mocks__|__fixtures__|fixtures?|testdata|test[-_]?targets?|vuln(?:erable)?[-_]?(?:fixtures?|apps?|targets?))\//i;
