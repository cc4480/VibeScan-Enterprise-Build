/** The team invitation email. */
import { escapeHtml } from "./mailerCore";
import { sendAccountMessage } from "./mailerAccount";

/**
 * Tells someone a SecScan user invited them to read that account's security reports, and links to accept. The owner's
 * address is the only thing in it that came from a user, and it is escaped. The link works only for the invited address.
 */
export async function sendTeamInviteEmail(to: string, ownerEmail: string, acceptUrl: string, role: "viewer" | "editor" = "viewer"): Promise<void> {
  const can = role === "editor"
    ? "You will be able to read their reports and monitored sites, download evidence packs, pause and resume their monitors, and file tickets from their reports. You will not be able to run scans, change settings or see billing."
    : "You will be able to read their reports and monitored sites and download evidence packs. You will not be able to run scans or change anything.";
  await sendAccountMessage(
    to,
    `${ownerEmail} invited you to view their security reports on SecScan`,
    {
      heading: "You have been invited to view security reports",
      body: `<strong>${escapeHtml(ownerEmail)}</strong> invited you to read their security reports on SecScan. ${can}`,
      ctaLabel: "Accept the invitation",
      ctaUrl: acceptUrl,
      footnote: `Sign in or create an account with this address (${escapeHtml(to)}) to accept: the invitation only works for it. If you were not expecting this, ignore this email and nothing will happen.`,
    },
    "team invitation",
  );
}
