/**
 * Boot-time checks for configuration that would otherwise fail one request at a time.
 *
 * ENCRYPTION_KEY was only read lazily, so a production deploy without it booted "healthy" and then threw
 * on the first sign-up, Google sign-in, unsubscribe link or credentialed scan. It is required in
 * production, so the process now says so at start instead.
 *
 * A key that is present but not 32 bytes of base64 is reported loudly and not fatal: sign-up and
 * unsubscribe links work with it today, and refusing to boot would turn a warning into an outage.
 */
export interface BootLog {
  error(obj: object, msg: string): void;
}

export function checkProductionConfig(log: BootLog, env: NodeJS.ProcessEnv = process.env): void {
  if (env["NODE_ENV"] !== "production") return;

  const key = env["ENCRYPTION_KEY"]?.trim();
  if (!key) {
    throw new Error(
      "ENCRYPTION_KEY is required in production and is not set. It protects stored scan logins, sign-up network hashes " +
        "and unsubscribe links. Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\"",
    );
  }
  if (Buffer.from(key, "base64").length !== 32) {
    log.error(
      { variable: "ENCRYPTION_KEY" },
      "ENCRYPTION_KEY does not decode to exactly 32 bytes of base64: scans with stored logins will fail until it is replaced",
    );
  }
}
