import { describe, it, expect } from "vitest";
import { getTableColumns } from "drizzle-orm";
import { usersTable } from "@workspace/db";
import { ALERT_COLUMNS } from "./emailPreferences";

/**
 * Deliberately does NOT mock @workspace/db, unlike every other test for this
 * route — that is the whole point of the file.
 *
 * The route builds its update as Record<string, boolean | string> and writes
 * column names as string literals, so the compiler cannot check them. Worse,
 * the route's own tests mock the database and assert that the recorded update
 * contains "notifyCveOptedOut" — which compares the constant against itself
 * and would pass just as happily if the column did not exist.
 *
 * A typo there does not fail loudly. It compiles, the tests stay green, the
 * settings screen animates the toggle, and the preference is never stored —
 * the user believes they turned an alert off and keeps receiving it. This
 * asserts the names against the real schema instead.
 */

describe("ALERT_COLUMNS", () => {
  const realColumns = Object.keys(getTableColumns(usersTable));

  it("names a column that actually exists for every alert kind", () => {
    for (const [field, column] of Object.entries(ALERT_COLUMNS)) {
      expect(realColumns, `${field} → "${column}" is not a column on users`)
        .toContain(column);
    }
  });

  it("covers every notify_* column the schema defines", () => {
    // The other direction: a column added to the schema but never wired into
    // the route is a preference the user can never set, which looks identical
    // to one that does not work.
    const notifyColumns = realColumns.filter((c) => c.startsWith("notify") && c.endsWith("OptedOut"));
    const mapped = Object.values(ALERT_COLUMNS) as string[];

    for (const col of notifyColumns) {
      expect(mapped, `${col} exists on users but no API field writes it`).toContain(col);
    }
  });

  it("maps each field to a distinct column", () => {
    // Two fields pointing at one column would make one toggle silently
    // overwrite the other.
    const mapped = Object.values(ALERT_COLUMNS);
    expect(new Set(mapped).size).toBe(mapped.length);
  });
});
