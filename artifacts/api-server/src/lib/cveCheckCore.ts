/** Shared finding constructor for the CVE checks. */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}
