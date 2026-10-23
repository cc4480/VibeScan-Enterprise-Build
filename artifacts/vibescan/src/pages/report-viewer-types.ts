import type { Report, ReportData, AiAnalysis } from "@workspace/api-client-react";

export type ReportResponse = Report;
export type ReportPayload = ReportData;
export type AiAnalysisData = AiAnalysis;
export type SortBy = "severity" | "category";
export type ViewMode = "grouped" | "flat";
