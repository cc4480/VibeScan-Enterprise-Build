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

/** Files under a directory the project does not own (dependencies, build output, fixtures). */
export const NOT_THE_PROJECTS_OWN = /(?:^|\/)(?:node_modules|vendor|third_party|dist|build|out|coverage|\.next|\.git|\.turbo|__tests__|__mocks__|__fixtures__|fixtures?|testdata)\//i;
