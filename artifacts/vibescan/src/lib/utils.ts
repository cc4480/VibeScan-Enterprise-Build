import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatSeverity(severity: string) {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

export function getSeverityColors(severity: string) {
  switch (severity.toLowerCase()) {
    case "critical":
      return "text-red-400 bg-red-400/10 border-red-400/20";
    case "high":
      return "text-orange-400 bg-orange-400/10 border-orange-400/20";
    case "medium":
      return "text-yellow-400 bg-yellow-400/10 border-yellow-400/20";
    case "low":
      return "text-blue-400 bg-blue-400/10 border-blue-400/20";
    case "info":
    default:
      return "text-gray-400 bg-gray-400/10 border-gray-400/20";
  }
}

export function getGradeColor(grade: string) {
  switch (grade.toUpperCase()) {
    case "A": return "text-emerald-400";
    case "B": return "text-lime-400";
    case "C": return "text-yellow-400";
    case "D": return "text-orange-400";
    case "F": return "text-red-400";
    default: return "text-muted-foreground";
  }
}
