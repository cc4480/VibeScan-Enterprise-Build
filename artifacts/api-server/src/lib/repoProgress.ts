/**
 * What a repository scan tells the live progress display while it runs: it listed the files, it has read this many
 * of them, this check finished with this result. Every number is the scan's own count at that moment; nothing is
 * estimated. The steps are shown as lines in the scan terminal and are not part of the saved report's test list
 * (TestLedger.progress), which keeps its single "GitHub source code secrets" record with the full source section.
 */
import type { TestRecord } from "./testLedger";

export type RepoProgress =
  | { kind: "listed"; treeFiles: number; toRead: number; binary: number; vendored: number; tooLarge: number; truncated: boolean }
  | { kind: "reading"; read: number; total: number; bytes: number }
  | { kind: "check"; name: string; files: number; findings: number; note?: string };

const GROUP = "repository";
const mb = (bytes: number) => (bytes >= 100_000 ? `${(bytes / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1000))} KB`);
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** One progress event as the line the terminal shows. */
export function progressRecord(e: RepoProgress): TestRecord {
  if (e.kind === "listed") {
    const left = [
      e.binary > 0 ? `${plural(e.binary, "binary file")}` : "",
      e.vendored > 0 ? `${e.vendored} in vendored or fixture folders` : "",
      e.tooLarge > 0 ? `${e.tooLarge} over the size limit` : "",
    ].filter(Boolean);
    return {
      group: GROUP, name: "Listing the repository's files", status: "ran", findings: 0, durationMs: 0,
      detail: `${plural(e.treeFiles, "file")} found, ${e.toRead} to read${left.length ? ` (left alone: ${left.join(", ")})` : ""}${e.truncated ? ". GitHub's file list was incomplete" : ""}`,
    };
  }
  if (e.kind === "reading") {
    return {
      group: GROUP, name: `Reading files (${e.read} of ${e.total})`, status: "ran", findings: 0, durationMs: 0,
      detail: `${e.read} of ${e.total} read, ${mb(e.bytes)}`,
    };
  }
  if (e.files === 0) {
    return { group: GROUP, name: `Check: ${e.name}`, status: "skipped", findings: 0, durationMs: 0, reason: e.note ?? "nothing of this kind in the repository" };
  }
  return {
    group: GROUP, name: `Check: ${e.name}`, status: "ran", findings: e.findings, durationMs: 0,
    detail: `${plural(e.files, "file")} checked${e.note ? `, ${e.note}` : ""}`,
  };
}
