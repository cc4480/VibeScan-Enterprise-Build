/** Certificate expiry probing. */
import * as tls from "node:tls";

// ── Certificate expiry ────────────────────────────────────────────────────────

export function certDaysRemaining(expiresAt: Date | null, now: Date = new Date()): number | null {
  if (!expiresAt) return null;
  if (Number.isNaN(expiresAt.getTime())) return null;
  return Math.ceil((expiresAt.getTime() - now.getTime()) / 86_400_000);
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
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:") return null;
    const host = url.hostname;
    const port = parseInt(url.port || "443", 10);

    return await new Promise<Date | null>((resolve) => {
      const socket = tls.connect(
        { host, port, servername: host, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          if (!cert || !cert.valid_to) {
            resolve(null);
            return;
          }
          const parsed = new Date(cert.valid_to);
          resolve(Number.isNaN(parsed.getTime()) ? null : parsed);
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
