/** Shapes of reconnaissance results. */
import type { ScanVulnerability } from "./scanner";

// ─── Public types ─────────────────────────────────────────────────────────────

export interface SubdomainEntry {
  subdomain: string;
  /** IPv4 address the subdomain resolves to, or null */
  ip: string | null;
  /** CNAME target if the subdomain is a canonical alias */
  cname: string | null;
  source: "crt.sh" | "wordlist";
}

export interface PortEntry {
  port: number;
  service: string;
  /** First ~256 bytes of banner received from the socket, or null */
  banner: string | null;
}

export interface DnsRecord {
  type: string;
  value: string;
  ttl?: number;
}

export interface ReconResult {
  subdomains: SubdomainEntry[];
  openPorts: PortEntry[];
  dnsRecords: DnsRecord[];
  reconDurationMs: number;
}

export interface ReconRunResult {
  recon: ReconResult;
  /** Vulnerabilities generated from dangerous open ports — merged into the main scan vuln list */
  vulns: ScanVulnerability[];
}
