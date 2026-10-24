import { useGetReport, getGetReportQueryKey } from "@workspace/api-client-react";
import { canFile, isViewOnly } from "./team";
import { brandOf, type Brand } from "./branding";

/**
 * Is this report open read-only, because the caller is a teammate of its owner? Read from the report the page already
 * loaded (the same query, so no extra request). False until the report has loaded, so owner-only actions never flash up
 * for a teammate only because they have to be hidden later; callers render nothing until they know.
 */
export function useViewOnly(reportId: string | undefined): { known: boolean; viewOnly: boolean; canFile: boolean } {
  const { data } = useGetReport(reportId ?? "", { query: { queryKey: getGetReportQueryKey(reportId ?? ""), enabled: Boolean(reportId) } });
  // `canFile`: the owner, or an editor on the owner's team. A viewer sees the report and nothing to act with.
  return { known: data !== undefined, viewOnly: isViewOnly(data), canFile: canFile(data) };
}

/** The report's branding (who prepared it), from the same loaded report. Null until it loads, and for an unbranded account. */
export function useReportBrand(reportId: string | undefined): Brand | null {
  const { data } = useGetReport(reportId ?? "", { query: { queryKey: getGetReportQueryKey(reportId ?? ""), enabled: Boolean(reportId) } });
  return brandOf(data);
}
