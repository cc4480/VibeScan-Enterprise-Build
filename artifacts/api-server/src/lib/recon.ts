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

import * as net from "node:net";
import * as dns from "node:dns/promises";
import { randomUUID } from "node:crypto";
import { logger } from "./logger";
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

// ─── Constants ────────────────────────────────────────────────────────────────

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const DNS_TIMEOUT_MS = 8_000;
const PORT_CONNECT_TIMEOUT_MS = 2_500;
const PORT_BANNER_WAIT_MS = 800;
const PORT_CONCURRENCY = 20;
const SUBDOMAIN_CONCURRENCY = 15;
const CRT_SH_TIMEOUT_MS = 12_000;
const SUBDOMAIN_CAP = 100; // max crt.sh results to resolve

const COMMON_SUBDOMAINS = [
  "www", "mail", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
  "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile",
  "test", "dev", "staging", "qa", "uat", "prod", "api", "api2",
  "app", "app2", "admin", "panel", "dashboard", "portal", "vpn",
  "cdn", "media", "static", "assets", "img", "images", "files",
  "beta", "old", "new", "shop", "store", "git", "gitlab",
  "cloud", "remote", "secure", "mx", "mail2", "support", "help",
  "status", "docs", "wiki", "blog", "forum", "auth", "login", "sso",
  "dev1", "dev2", "stage", "sandbox", "preview", "demo",
];

interface PortSpec {
  port: number;
  service: string;
  dangerous?: {
    severity: "critical" | "high" | "medium";
    description: string;
    solution: string;
    cweId: string;
    cvssScore: number;
    wstgId?: string;
  };
}

const TOP_PORTS: PortSpec[] = [
  { port: 21,  service: "FTP" },
  { port: 22,  service: "SSH" },
  {
    port: 23, service: "Telnet",
    dangerous: {
      severity: "critical",
      description: "Telnet transmits all data — including usernames, passwords, and commands — in plaintext. Any observer on the network path can capture credentials in real time.",
      solution: "Disable Telnet immediately and replace with SSH. Block port 23 at your firewall: `systemctl disable telnet && systemctl stop telnet`.",
      cweId: "CWE-319", cvssScore: 9.8, wstgId: "WSTG-CONF-06",
    },
  },
  { port: 25,  service: "SMTP" },
  { port: 53,  service: "DNS" },
  { port: 80,  service: "HTTP" },
  { port: 110, service: "POP3" },
  { port: 143, service: "IMAP" },
  { port: 443, service: "HTTPS" },
  {
    port: 445, service: "SMB",
    dangerous: {
      severity: "critical",
      description: "SMB (Windows file sharing) is exposed to the public internet. SMB was the vector for the WannaCry and NotPetya ransomware outbreaks via the EternalBlue exploit. Publicly exposed SMB is one of the highest-risk configurations possible.",
      solution: "Block port 445 at your firewall immediately — SMB must never be exposed to the public internet. Use a VPN for any remote file-sharing access.",
      cweId: "CWE-284", cvssScore: 10.0, wstgId: "WSTG-CONF-06",
    },
  },
  { port: 465, service: "SMTPS" },
  { port: 587, service: "SMTP Submission" },
  { port: 993, service: "IMAPS" },
  { port: 995, service: "POP3S" },
  {
    port: 1433, service: "MSSQL",
    dangerous: {
      severity: "high",
      description: "Microsoft SQL Server is exposed to the public internet. Attackers routinely brute-force MSSQL credentials and exploit SQL injection remotely against publicly accessible instances.",
      solution: "Block port 1433 at your firewall. Databases must only be accessible from the application tier on a private network. Use a jump host or VPN for DBA access.",
      cweId: "CWE-284", cvssScore: 8.1,
    },
  },
  {
    port: 1521, service: "Oracle DB",
    dangerous: {
      severity: "high",
      description: "Oracle Database listener is exposed to the public internet. Public exposure allows remote brute-force attacks and exploitation of Oracle-specific vulnerabilities.",
      solution: "Block port 1521 at your firewall. Restrict Oracle listener access to the application subnet only.",
      cweId: "CWE-284", cvssScore: 8.1,
    },
  },
  {
    port: 2375, service: "Docker API (unencrypted)",
    dangerous: {
      severity: "critical",
      description: "The Docker daemon REST API is exposed without TLS on port 2375. An attacker can create privileged containers, mount the host filesystem, escape to the host OS, and achieve full system compromise — no credentials required.",
      solution: "Stop Docker and remove the `-H tcp://0.0.0.0:2375` flag immediately. Use Unix socket + mutual TLS on port 2376 only if remote access is needed, and restrict to known IPs with firewall rules.",
      cweId: "CWE-284", cvssScore: 10.0,
    },
  },
  {
    port: 2376, service: "Docker API (TLS)",
    dangerous: {
      severity: "medium",
      description: "The Docker daemon TLS API is exposed on port 2376. If mutual TLS (client certificate authentication) is not properly configured, this may allow unauthenticated container management.",
      solution: "Ensure mTLS is configured with client certificate validation. Restrict access to known management IPs with firewall rules.",
      cweId: "CWE-284", cvssScore: 5.9,
    },
  },
  { port: 3000, service: "Dev Server / Node.js" },
  {
    port: 3306, service: "MySQL",
    dangerous: {
      severity: "high",
      description: "MySQL database server is exposed to the public internet. This allows remote credential brute-forcing and direct exploitation of database vulnerabilities.",
      solution: "Block port 3306 at your firewall. Bind MySQL to 127.0.0.1 in mysqld.cnf (`bind-address = 127.0.0.1`). Use SSH tunnels for remote DBA access.",
      cweId: "CWE-284", cvssScore: 8.1,
    },
  },
  {
    port: 3389, service: "RDP",
    dangerous: {
      severity: "high",
      description: "Remote Desktop Protocol (RDP) is exposed to the internet. RDP is one of the most commonly attacked services — ransomware groups actively scan for and brute-force exposed RDP endpoints.",
      solution: "Block port 3389 from public internet access. Use a VPN or Bastion/Jump host for remote access. If RDP must be exposed, enable Network Level Authentication and implement account lockout policies.",
      cweId: "CWE-284", cvssScore: 8.1, wstgId: "WSTG-ATHN-03",
    },
  },
  { port: 4443, service: "Alt HTTPS" },
  {
    port: 5432, service: "PostgreSQL",
    dangerous: {
      severity: "high",
      description: "PostgreSQL database server is exposed to the public internet. Public exposure allows remote credential attacks and exploitation of database-level vulnerabilities.",
      solution: "Block port 5432 at your firewall. Set `listen_addresses = 'localhost'` in postgresql.conf. PostgreSQL should only be reachable from the application tier on a private network.",
      cweId: "CWE-284", cvssScore: 8.1,
    },
  },
  {
    port: 5984, service: "CouchDB",
    dangerous: {
      severity: "high",
      description: "CouchDB HTTP API is exposed to the public internet. Older CouchDB versions allow unauthenticated admin access (CVE-2017-12635). Even current versions expose all database contents without a firewall.",
      solution: "Block port 5984 from the public internet. Set `bind_address = 127.0.0.1` in the CouchDB config and use an authenticated reverse proxy for any external access.",
      cweId: "CWE-284", cvssScore: 7.5,
    },
  },
  {
    port: 6379, service: "Redis",
    dangerous: {
      severity: "critical",
      description: "Redis is exposed to the public internet. Redis has no authentication by default — an attacker can read and overwrite all cached data, execute Lua scripts, and in some configurations write cron jobs or SSH authorized_keys to achieve remote code execution.",
      solution: "Block port 6379 at your firewall immediately. Bind Redis to 127.0.0.1 in redis.conf (`bind 127.0.0.1`). Set a strong password with `requirepass`. Redis must never be internet-facing.",
      cweId: "CWE-284", cvssScore: 10.0,
    },
  },
  { port: 8000, service: "Alt HTTP" },
  { port: 8080, service: "Alt HTTP / Proxy" },
  { port: 8443, service: "Alt HTTPS" },
  { port: 8888, service: "Jupyter / Dev Server" },
  { port: 9000, service: "SonarQube / PHP-FPM" },
  {
    port: 9200, service: "Elasticsearch",
    dangerous: {
      severity: "critical",
      description: "Elasticsearch HTTP API is exposed to the public internet. By default Elasticsearch has no authentication — an unauthenticated attacker can read, modify, or delete all indexed data and administer the cluster. Thousands of exposed Elasticsearch instances have been wiped and ransomed.",
      solution: "Block port 9200 with your firewall. Enable X-Pack security (`xpack.security.enabled: true`) and require authentication. Place Elasticsearch behind a private network.",
      cweId: "CWE-284", cvssScore: 9.8,
    },
  },
  {
    port: 11211, service: "Memcached",
    dangerous: {
      severity: "high",
      description: "Memcached is exposed to the public internet. Memcached has no authentication — an attacker can read or poison all cached data. Exposed Memcached servers have been abused in record-breaking DDoS amplification attacks (amplification factor up to 51,000x).",
      solution: "Block port 11211 at your firewall. Bind Memcached to 127.0.0.1 (`-l 127.0.0.1`). Memcached must never be internet-facing.",
      cweId: "CWE-284", cvssScore: 8.1,
    },
  },
  {
    port: 27017, service: "MongoDB",
    dangerous: {
      severity: "critical",
      description: "MongoDB is exposed to the public internet. MongoDB has no authentication by default — an attacker can read, modify, and delete all databases with no credentials. Exposed MongoDB instances have caused numerous large-scale data breaches and ransom attacks.",
      solution: "Block port 27017 at your firewall immediately. Enable MongoDB authentication (`security.authorization: enabled` in mongod.conf). Bind to 127.0.0.1 only.",
      cweId: "CWE-284", cvssScore: 10.0,
    },
  },
];

// ─── SSRF guard ───────────────────────────────────────────────────────────────

function isPrivateIp(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    ip === "::1" ||
    /^fc00:/i.test(ip) ||
    /^fd[0-9a-f]{2}:/i.test(ip) ||
    ip === "0.0.0.0"
  );
}

// ─── Port scanner ─────────────────────────────────────────────────────────────

async function scanPort(
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

async function scanPorts(host: string): Promise<PortEntry[]> {
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

// ─── DNS enumeration via Cloudflare DoH ──────────────────────────────────────

async function dohQuery(
  name: string,
  type: string,
): Promise<Array<{ value: string; ttl: number }>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);
  try {
    const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}&ct=application/dns-json`;
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    if (!res.ok) return [];
    const json = (await res.json()) as {
      Answer?: Array<{ data: string; TTL: number }>;
    };
    return (json.Answer ?? []).map((a) => ({
      value: a.data.replace(/\.$/, ""),
      ttl: a.TTL,
    }));
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

async function enumerateDns(domain: string): Promise<DnsRecord[]> {
  const queries: Array<{ type: string; name: string }> = [
    { type: "A",    name: domain },
    { type: "AAAA", name: domain },
    { type: "MX",   name: domain },
    { type: "NS",   name: domain },
    { type: "TXT",  name: domain },
    { type: "SOA",  name: domain },
    { type: "CAA",  name: domain },
    { type: "TXT",  name: `_dmarc.${domain}` },
  ];

  const results = await Promise.all(
    queries.map(async ({ type, name }) => {
      const answers = await dohQuery(name, type);
      return answers.map((a) => ({
        type,
        value: name !== domain ? `[${name}] ${a.value}` : a.value,
        ttl: a.ttl,
      }));
    }),
  );

  return results.flat();
}

// ─── Subdomain enumeration ────────────────────────────────────────────────────

async function fetchSubdomainsFromCrtSh(domain: string): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CRT_SH_TIMEOUT_MS);
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return [];
    const json = (await res.json()) as Array<{ name_value: string }>;
    const seen = new Set<string>();
    for (const entry of json) {
      for (const raw of entry.name_value.split("\n")) {
        const sub = raw.trim().toLowerCase().replace(/^\*\./, "");
        if (sub && sub.endsWith(`.${domain}`) && !seen.has(sub)) {
          seen.add(sub);
        }
      }
    }
    return [...seen];
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

async function resolveSubdomain(
  sub: string,
): Promise<{ ip: string | null; cname: string | null }> {
  try {
    const addresses = await dns.lookup(sub, { all: true, family: 4 });
    return { ip: (addresses as Array<{ address: string }>)[0]?.address ?? null, cname: null };
  } catch {
    try {
      const result = await dns.resolveCname(sub);
      return { ip: null, cname: (result as string[])[0] ?? null };
    } catch {
      return { ip: null, cname: null };
    }
  }
}

async function enumerateSubdomains(domain: string): Promise<SubdomainEntry[]> {
  const seen = new Set<string>();
  const entries: SubdomainEntry[] = [];

  const crtShSubs = await fetchSubdomainsFromCrtSh(domain);

  // Build deduplicated task list: crt.sh first, then wordlist for any not already found
  const allTasks: Array<{ sub: string; source: "crt.sh" | "wordlist" }> = [];

  for (const s of crtShSubs.slice(0, SUBDOMAIN_CAP)) {
    if (!seen.has(s)) { seen.add(s); allTasks.push({ sub: s, source: "crt.sh" }); }
  }
  for (const w of COMMON_SUBDOMAINS) {
    const s = `${w}.${domain}`;
    if (!seen.has(s)) { seen.add(s); allTasks.push({ sub: s, source: "wordlist" }); }
  }

  for (let i = 0; i < allTasks.length; i += SUBDOMAIN_CONCURRENCY) {
    const batch = allTasks.slice(i, i + SUBDOMAIN_CONCURRENCY);
    const resolved = await Promise.all(
      batch.map(async ({ sub, source }) => {
        const { ip, cname } = await resolveSubdomain(sub);
        if (!ip && !cname) return null;
        return { subdomain: sub, ip, cname, source } satisfies SubdomainEntry;
      }),
    );
    for (const r of resolved) {
      if (r) entries.push(r);
    }
  }

  return entries;
}

// ─── Dangerous port → vulnerability ──────────────────────────────────────────

function portVulns(openPorts: PortEntry[]): ScanVulnerability[] {
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

// ─── Main export ─────────────────────────────────────────────────────────────

export async function runRecon(targetUrl: string): Promise<ReconRunResult> {
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
    skipPortScan
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
    recon: { subdomains, openPorts, dnsRecords, reconDurationMs },
    vulns: portVulns(openPorts),
  };
}
