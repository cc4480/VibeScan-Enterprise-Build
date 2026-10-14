import type { Category, Check } from "./learn-types";
import { LEARN_CATEGORIES_A } from "./learn-data-a";
import { LEARN_CATEGORIES_B } from "./learn-data-b";
import { LEARN_CATEGORIES_C } from "./learn-data-c";

/** Update when the checks are reviewed against the scanner. Shown on /learn and in its structured data. */
export const LEARN_LAST_REVIEWED = "September 24, 2026";

export const LEARN_CATEGORIES: Category[] = [...LEARN_CATEGORIES_A, ...LEARN_CATEGORIES_B, ...LEARN_CATEGORIES_C];

export const LEARN_CHECKS: Check[] = LEARN_CATEGORIES.flatMap((c) => c.checks);

export function checkById(id: string): Check | undefined {
  return LEARN_CHECKS.find((c) => c.id === id);
}

export function categoryOfCheck(id: string): Category | undefined {
  return LEARN_CATEGORIES.find((cat) => cat.checks.some((c) => c.id === id));
}

/** Every check has its own page, at an address that names it. */
export function checkPath(id: string): string {
  return `/learn/${id}`;
}

/** Under 60 characters, so a search result shows all of it. */
export function checkPageTitle(c: Check): string {
  const long = `${c.shortTitle}: what it is and how to fix it — SecScan.us`;
  return long.length <= 60 ? long : `${c.shortTitle} explained — SecScan.us`;
}

/**
 * The check's own opening sentence, cut to fit a search result. The "what it is"
 * text is written to answer the question first, so it is also the answer an
 * answer engine would quote.
 */
export function checkPageDescription(c: Check): string {
  const first = c.what.split(/(?<=\.)\s/)[0] ?? c.what;
  if (first.length <= 155) return first;
  const cut = first.slice(0, 154);
  return `${cut.slice(0, cut.lastIndexOf(" "))}…`;
}

/** What the server needs to serve a check's page without loading this data: written at build time. */
export interface CheckManifestEntry {
  id: string;
  title: string;
  description: string;
  /** The check's own name, for the breadcrumb and headline. */
  name: string;
  /** Plain-text answers for the page's FAQ markup. */
  what: string;
  fix: string;
}

export function checkManifest(): CheckManifestEntry[] {
  return LEARN_CHECKS.map((c) => ({
    id: c.id,
    title: checkPageTitle(c),
    description: checkPageDescription(c),
    name: c.title,
    what: c.what,
    fix: c.fix,
  }));
}
