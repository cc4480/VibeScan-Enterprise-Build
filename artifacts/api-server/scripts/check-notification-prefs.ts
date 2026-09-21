/**
 * Did a notification preference actually reach the database?
 *
 * Reads only the preference columns and a truncated user id — no email
 * addresses, no names. Enough to tell a stored preference from a toggle that
 * only animated, which is the one thing clicking cannot distinguish.
 *
 * MUST RUN INSIDE RAILWAY. DATABASE_URL points at postgres.railway.internal,
 * which only resolves on Railway's private network — `railway run` injects the
 * variable but leaves you on your own machine, so it fails with ENOTFOUND.
 * Use the service shell, or a one-off command on the deployed container.
 *
 * For a single signed-in user there is a quicker answer that needs no database
 * access at all: open /api/account/email-preferences in the browser. It returns
 * exactly what is stored.
 */
import { db } from "@workspace/db";
import { sql } from "drizzle-orm";

const changed = await db.execute(sql`
  SELECT
    left(id, 8)                        AS user_prefix,
    alert_emails_opted_out             AS master_off,
    notify_cve_opted_out               AS cve_off,
    notify_regression_opted_out        AS regression_off,
    notify_cert_expiry_opted_out       AS cert_off,
    notify_scan_complete_opted_out     AS scan_off,
    notify_min_severity                AS min_severity
  FROM users
  WHERE alert_emails_opted_out
     OR notify_cve_opted_out
     OR notify_regression_opted_out
     OR notify_cert_expiry_opted_out
     OR notify_scan_complete_opted_out
     OR notify_min_severity <> 'info'
  ORDER BY id
`);

const rows = changed.rows ?? changed;

if (rows.length === 0) {
  console.log("NO PREFERENCES STORED — every user is still at the defaults.");
  console.log("If you changed a toggle and this is empty, the save never reached the database.");
} else {
  console.log(`${rows.length} user(s) with a non-default preference:\n`);
  console.table(rows);
}

const totals = await db.execute(sql`SELECT count(*)::int AS n FROM users`);
const totalRows = totals.rows ?? totals;
console.log(`\n(${totalRows[0].n} users total)`);

process.exit(0);
