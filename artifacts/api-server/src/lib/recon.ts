/**
 * Phase 1 Reconnaissance — passive + active black-box intelligence gathering.
 *
 * Three concurrent tracks run in parallel:
 *   1. DNS enumeration  — A, AAAA, MX, NS, TXT (SPF/DMARC), SOA, CAA via Cloudflare DoH
 *   2. Subdomain enum   — crt.sh certificate transparency logs + wordlist DNS brute-force
 *   3. Port scanning    — TCP-connect scan of top 30 ports with banner grabbing
 *
 * SSRF protection: the target hostname is resolved to an IP before port scanning.
 * If the resolved IP falls in an RFC-1918/loopback/link-local range the port scan
 * is skipped entirely — we never probe internal infrastructure.
 *
 * All network operations run with hard timeouts so a slow/unresponsive target
 * cannot stall the wider scan pipeline.
 */

import * as dns from "node:dns/promises";
import { logger } from "./logger";
import { type SubdomainEntry, type PortEntry, type DnsRecord, type ReconRunResult } from "./reconTypes";
import { isPrivateIp, scanPorts, labelEdgePorts, portVulns } from "./reconPorts";
import { enumerateDns, enumerateSubdomains } from "./reconDns";
export { EDGE_PORT_LABEL, labelEdgePorts } from "./reconPorts";
export type { SubdomainEntry, PortEntry, DnsRecord, ReconResult, ReconRunResult } from "./reconTypes";

// ─── Main export ─────────────────────────────────────────────────────────────

export async function runRecon(
  targetUrl: string,
  // A TCP sweep of someone else's host is reconnaissance against them, not a
  // visit to their site, so it waits for the same ownership proof the
  // offensive HTTP probes do. DNS and subdomain enumeration stay: both read
  // public records without touching the target.
  allowPortScan: boolean,
): Promise<ReconRunResult> {
  const startedAt = Date.now();
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    throw new Error(`[recon] Invalid target URL: ${targetUrl}`);
  }

  const log = logger.child({ hostname });
  log.info("[recon] Starting reconnaissance");

  // Resolve IP and apply SSRF guard before port scanning
  let resolvedIp: string | null = null;
  let skipPortScan = false;

  try {
    const result = await dns.lookup(hostname, { family: 4 }) as { address: string };
    resolvedIp = result.address;
    if (isPrivateIp(resolvedIp)) {
      log.warn({ ip: resolvedIp }, "[recon] Target resolves to private IP — port scan skipped (SSRF guard)");
      skipPortScan = true;
    }
  } catch {
    log.warn("[recon] Could not resolve target hostname — port scan skipped");
    skipPortScan = true;
  }

  const domain = hostname.replace(/^www\./, "");

  const [dnsRecords, subdomains, openPorts] = await Promise.all([
    enumerateDns(domain).catch((err) => {
      log.warn({ err }, "[recon] DNS enumeration failed");
      return [] as DnsRecord[];
    }),
    enumerateSubdomains(domain).catch((err) => {
      log.warn({ err }, "[recon] Subdomain enumeration failed");
      return [] as SubdomainEntry[];
    }),
    skipPortScan || !allowPortScan
      ? Promise.resolve([] as PortEntry[])
      : scanPorts(resolvedIp!).catch((err) => {
          log.warn({ err }, "[recon] Port scan failed");
          return [] as PortEntry[];
        }),
  ]);

  const reconDurationMs = Date.now() - startedAt;

  log.info(
    { dnsRecords: dnsRecords.length, subdomains: subdomains.length, openPorts: openPorts.length, reconDurationMs },
    "[recon] Reconnaissance complete",
  );

  return {
    recon: { subdomains, openPorts: labelEdgePorts(openPorts, resolvedIp), dnsRecords, reconDurationMs },
    vulns: portVulns(openPorts),
  };
}