import { useQuery } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { anyPending, type VerificationStatus } from "./verify-fix";

/**
 * The re-check results for one report. Shared by the per-finding button and the report
 * page itself, so both read the same cached query and the page can move findings that
 * are verified fixed out of the open lists the moment a check finishes.
 */
export function useVerifications(reportId: string | undefined) {
  return useQuery({
    queryKey: ["verifications", reportId],
    queryFn: () => customFetch<{ verifications: VerificationStatus[] }>(`/api/reports/${reportId}/verifications`),
    enabled: Boolean(reportId),
    // Poll only while a check is running.
    refetchInterval: (q) => (anyPending(q.state.data?.verifications) ? 3000 : false),
  });
}
