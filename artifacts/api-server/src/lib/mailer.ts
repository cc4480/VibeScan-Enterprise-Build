/**
 * Email notifications via Resend API.
 * Used to send report-ready emails after deep/pack scan completion,
 * and monitor subscription alerts (CVE matches, weekly scan queued).
 * Requires RESEND_API_KEY environment variable.
 */

export { buildHtml, sendReportReadyEmail } from "./mailerReport";
export { sendMonitorCveAlertEmail, sendRegressionAlertEmail } from "./mailerCve";
export { sendCertExpiryEmail, sendAvailabilityEmail } from "./mailerHealth";
export { sendDriftEmail, sendMonitorScanQueuedEmail } from "./mailerDrift";
export { sendPurchaseReceiptEmail, sendEmailVerification } from "./mailerAccount";
export { sendTeamInviteEmail } from "./mailerTeam";
export { sendLoginCode, sendPasswordReset, sendSignupExistingAccountEmail } from "./mailerAccountAccess";
export { setMarketingSubscription, addToMarketingAudience, sendWelcomeEmail, sendPaymentsLiveEmail } from "./mailerMarketing";
export type { RegressionItem } from "./mailerCve";
