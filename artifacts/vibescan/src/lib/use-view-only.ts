import { useGetReport, getGetReportQueryKey } from "@workspace/api-client-react";
import { isViewOnly } from "./team";

/**
 * Is this report open read-only, because the caller is a teammate of its owner? Read from the report the page already
 * loaded (the same query, so no extra request). False until the report has loaded, so owner-only actions never flash up
 * for a teammate only because they have to be hidden later; callers render nothing until they know.
 */
export function useViewOnly(reportId: string | undefined): { known: boolean; viewOnly: boolean } {
  const { data } = useGetReport(reportId ?? "", { query: { queryKey: getGetReportQueryKey(reportId ?? ""), enabled: Boolean(reportId) } });
  return { known: data !== undefined, viewOnly: isViewOnly(data) };
}
