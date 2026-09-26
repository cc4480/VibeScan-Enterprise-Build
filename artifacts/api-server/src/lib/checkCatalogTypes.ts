/** Shapes and the row helper for the check catalog. Kept apart so the data files can import them without a cycle. */

export type CheckSeverity = "critical" | "high" | "medium" | "low" | "info" | "varies";

export interface CatalogCheck {
  /** The finding's name as the report shows it (a fixed prefix where the name has variable parts). */
  name: string;
  severity: CheckSeverity;
  /** Overrides the test's category, for the few tests whose checks span two (headers vs cookies). */
  category?: string;
  /** Source file (in src/lib) that raises it, when not the test's own. */
  file?: string;
  /** Text that must appear in that file: the exact literal, or the fixed start of a dynamic name. */
  needle?: string;
}

export interface CatalogTest {
  /** The ledger test's name; a record matches when its name equals this or starts with it. */
  test: string;
  /** Finding category, used to colour the test the same way the report colours its findings. */
  category: string;
  /** Source file (in src/lib) that raises this test's findings. */
  file: string;
  checks: CatalogCheck[];
}

/** Shorthand for the data files: [severity, name, needle?, file?, category?]. */
export type Row = [CheckSeverity, string, string?, string?, string?];

export function test(testName: string, category: string, file: string, rows: Row[]): CatalogTest {
  return {
    test: testName,
    category,
    file,
    checks: rows.map(([severity, name, needle, fileOverride, cat]) => ({
      name,
      severity,
      ...(needle ? { needle } : {}),
      ...(fileOverride ? { file: fileOverride } : {}),
      ...(cat ? { category: cat } : {}),
    })),
  };
}
