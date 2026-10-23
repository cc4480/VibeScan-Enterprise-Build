import { customFetch } from "@workspace/api-client-react";

/**
 * The public grade badge for a report: a small image showing the grade and the scan date,
 * for a README or a footer. It has its own token, so pasting it never exposes the report.
 */
export interface ReportBadge {
  token: string;
  imageUrl: string;
  markdown: string;
  html: string;
}

/**
 * Get the report's badge, creating it the first time. Asking twice returns the same one.
 * Refused (409, code "badge_needs_verified_scan") unless the scan was of a domain the account
 * has verified.
 */
export const getReportBadge = (reportId: string) =>
  customFetch<ReportBadge>(`/api/reports/${encodeURIComponent(reportId)}/badge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });

/** Take the badge down. The image then reads "badge not found" wherever it was pasted. */
export const removeReportBadge = (reportId: string) =>
  customFetch<void>(`/api/reports/${encodeURIComponent(reportId)}/badge`, { method: "DELETE" });
