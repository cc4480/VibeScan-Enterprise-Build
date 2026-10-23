/** Certificate expiry probing. */
import * as tls from "node:tls";
import { vettedLookup } from "./pinnedDispatcher";
import { checkScanTarget } from "./ssrfGuard";

// ── Certificate expiry ────────────────────────────────────────────────────────

export function certDaysRemaining(expiresAt: Date | null, now: Date = new Date()): number | null {
  if (!expiresAt) return null;
  if (Number.isNaN(expiresAt.getTime())) return null;
  return Math.ceil((expiresAt.getTime() - now.getTime()) / 86_400_000);
}

/**
 * Certificates this short-lived are issued by ACME services (Let's Encrypt, ZeroSSL, Google
 * Trust Services) and renewed automatically, normally when about a third of the lifetime is left:
 * 30 days for a 90-day certificate. A 30-day warning on one of those fires on every cycle, hours
 * before the renewal that makes it moot, and teaches people to ignore the alert. The 14 and 7 day
 * warnings stay: a short-lived certificate still unrenewed at 14 days means the renewal failed.
 */
export const SHORT_LIVED_CERT_DAYS = 100;

/** Days before expiry at which to warn, given what is known about the certificate's lifetime. */
export function certAlertThresholds(issuedAt: Date | null | undefined, expiresAt: Date): readonly number[] {
  if (issuedAt && !Number.isNaN(issuedAt.getTime())) {
    const lifetimeDays = (expiresAt.getTime() - issuedAt.getTime()) / 86_400_000;
    if (lifetimeDays > 0 && lifetimeDays <= SHORT_LIVED_CERT_DAYS) return [14, 7];
  }
  return [30, 14, 7];
}

// ── The probe itself ──────────────────────────────────────────────────────────

export const PULSE_TIMEOUT_MS = 10_000;

/**
 * Probe the TLS certificate expiry for an https URL.
 *
 * rejectUnauthorized is false on purpose: an expired or self-signed
 * certificate is precisely what we are trying to report, and refusing the
 * handshake would turn the finding into a null.
 */
export async function probeCertExpiry(rawUrl: string): Promise<Date | null> {
  return (await probeCertDates(rawUrl))?.expiresAt ?? null;
}

/** Expiry plus issue date, so the alert can tell an auto-renewing certificate from a yearly one. */
export async function probeCertDates(rawUrl: string): Promise<{ expiresAt: Date; issuedAt: Date | null } | null> {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:") return null;
    // The lookup below vets names, but tls.connect never consults it for an IP literal, so the literal is judged here.
    if (!(await checkScanTarget(rawUrl)).ok) return null;
    const host = url.hostname;
    const port = parseInt(url.port || "443", 10);

    return await new Promise<{ expiresAt: Date; issuedAt: Date | null } | null>((resolve) => {
      // The vetted lookup judges the address the socket then opens to, so a name that re-resolves to a
      // private address between the URL check and this connection is refused rather than dialled.
      const socket = tls.connect(
        { host, port, servername: host, rejectUnauthorized: false, lookup: vettedLookup as never },
        () => {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          if (!cert || !cert.valid_to) {
            resolve(null);
            return;
          }
          const expiresAt = new Date(cert.valid_to);
          const issuedAt = cert.valid_from ? new Date(cert.valid_from) : null;
          resolve(
            Number.isNaN(expiresAt.getTime())
              ? null
              : { expiresAt, issuedAt: issuedAt && !Number.isNaN(issuedAt.getTime()) ? issuedAt : null },
          );
        },
      );
      socket.on("error", () => resolve(null));
      socket.setTimeout(PULSE_TIMEOUT_MS, () => {
        socket.destroy();
        resolve(null);
      });
    });
  } catch {
    return null;
  }
}
