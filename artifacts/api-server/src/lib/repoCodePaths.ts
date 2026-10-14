/**
 * Which files the code-pattern rules read, and the shape of a rule. In their own file so the rule modules can share
 * them without importing each other.
 */
import { NOT_THE_PROJECTS_OWN } from "./repoFinding";
import type { ScanVulnerability } from "./scanner";

export const isCodePath = (p: string) =>
  /\.(?:[cm]?[jt]sx?|vue|svelte)$/i.test(p) && !/\.d\.ts$|\.min\.|\.(?:test|spec|stories)\.[cm]?[jt]sx?$/i.test(p) && !NOT_THE_PROJECTS_OWN.test(p);
export const isEnvFilePath = (p: string) => /(?:^|\/)\.env(?:\.[\w.-]+)?$/i.test(p) && !/\.(?:example|sample|template|dist|tmpl)$/i.test(p);

export interface Rule {
  name: string;
  /** `deliberate`: the code around the match says the pattern is intended; reported as information, not as a flaw. */
  test: (path: string, text: string) => { detail: string; deliberate?: string } | null;
  severity: ScanVulnerability["severity"];
  category: string;
  cweId: string;
  cvssScore: number;
  confidence: number;
  description: string;
  solution: string;
}
