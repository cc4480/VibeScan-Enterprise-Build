export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Check {
  id: string;
  title: string;
  shortTitle: string;
  severity: Severity;
  cweId?: string;
  cvssScore?: number;
  owasp?: string;
  wstgId?: string;
  what: string;
  why: string;
  howTested: string;
  fix: string;
  fixCode?: string;
  fixCodeLang?: string;
  learnMore?: string;
}

export interface Category {
  id: string;
  label: string;
  description: string;
  icon: React.ElementType;
  checks: Check[];
}
