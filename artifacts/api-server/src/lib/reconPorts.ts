/** Port scanning of the target's host and the findings for dangerous open ports. */
import * as net from "node:net";
import { randomUUID } from "node:crypto";
import { isCloudflareIp } from "./cloudflareIps";
import type { ScanVulnerability } from "./scanner";
import { TOP_PORTS } from "./recon-data";
import { type PortEntry } from "./reconTypes";
import { isPrivateAddress } from "./ssrfGuard";

export const PORT_CONNECT_TIMEOUT_MS = 2_500;

export const PORT_BANNER_WAIT_MS = 800;

export const PORT_CONCURRENCY = 20;

// ─── SSRF guard ───────────────────────────────────────────────────────────────

/**
 * The same private/reserved list the rest of the scanner uses (CGNAT, benchmarking, multicast, reserved and
 * IPv6 forms included), plus the unspecified address. "0.0.0.0" reaches localhost on Linux, so it is named
 * explicitly and never left to the range rules.
 */
export function isPrivateIp(ip: string): boolean {
  return ip === "0.0.0.0" || isPrivateAddress(ip);
}

// ─── Port scanner ─────────────────────────────────────────────────────────────

export async function scanPort(
  host: string,
  port: number,
): Promise<{ open: boolean; banner: string | null }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";
    let resolved = false;
    let connected = false;
    let bannerTimer: ReturnType<typeof setTimeout> | null = null;

    const finish = (open: boolean) => {
      if (resolved) return;
      resolved = true;
      if (bannerTimer) clearTimeout(bannerTimer);
      socket.destroy();
      resolve({ open, banner: open && banner ? banner.slice(0, 256).trim() : null });
    };

    socket.setTimeout(PORT_CONNECT_TIMEOUT_MS);

    socket.on("connect", () => {
      connected = true;
      // Give the server a moment to send an unsolicited banner
      bannerTimer = setTimeout(() => finish(true), PORT_BANNER_WAIT_MS);
    });

    socket.on("data", (data) => {
      banner += data.toString("utf8", 0, 512);
      if (connected) finish(true);
    });

    socket.on("timeout", () => {
      if (connected) finish(true); // connected but no banner → port is still open
      else finish(false);
    });

    socket.on("error", () => finish(false));

    socket.connect(port, host);
  });
}

export async function scanPorts(host: string): Promise<PortEntry[]> {
  const open: PortEntry[] = [];
  const specs = [...TOP_PORTS];

  for (let i = 0; i < specs.length; i += PORT_CONCURRENCY) {
    const batch = specs.slice(i, i + PORT_CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (spec) => {
        const { open: isOpen, banner } = await scanPort(host, spec.port);
        return isOpen ? { port: spec.port, service: spec.service, banner } : null;
      }),
    );
    for (const r of results) {
      if (r) open.push(r);
    }
  }

  return open;
}

// ─── Ports behind a CDN ───────────────────────────────────────────────

/**
 * For a site proxied by Cloudflare the address we resolve is Cloudflare's, so the "open ports" are
 * its edge listening for that site (it answers 8080 and 8443 for every proxied domain), not
 * anything on the owner's server. Left unlabelled, a report on a proxied site lists ports like 8080
 * and 8443 as if the owner had opened them. The label goes on the service name, which every
 * consumer already shows, so no schema changes.
 */
export const EDGE_PORT_LABEL = " — Cloudflare edge";

export function labelEdgePorts(openPorts: PortEntry[], resolvedIp: string | null): PortEntry[] {
  if (!resolvedIp || !isCloudflareIp(resolvedIp)) return openPorts;
  return openPorts.map((p) => ({ ...p, service: `${p.service}${EDGE_PORT_LABEL}` }));
}

// ─── Dangerous port → vulnerability ──────────────────────────────────────────

export function portVulns(openPorts: PortEntry[]): ScanVulnerability[] {
  return openPorts.flatMap((p) => {
    const spec = TOP_PORTS.find((s) => s.port === p.port);
    if (!spec?.dangerous) return [];
    const d = spec.dangerous;
    return [{
      id: randomUUID(),
      name: `Exposed ${spec.service} Service (port ${p.port})`,
      severity: d.severity,
      category: "Network Exposure",
      description: d.description,
      evidence: [
        `Port ${p.port}/tcp is open (${spec.service})`,
        p.banner ? `Banner: ${p.banner}` : null,
      ].filter(Boolean).join("\n"),
      solution: d.solution,
      cweId: d.cweId,
      cvssScore: d.cvssScore,
      wstgId: d.wstgId ?? null,
      confidence: 95,
    } satisfies ScanVulnerability];
  });
}
