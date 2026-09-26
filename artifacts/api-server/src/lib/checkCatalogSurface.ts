/** The checks on what the app exposes beyond its headers: secrets, APIs, data stores, software, access control. */
import { test, type CatalogTest } from "./checkCatalogTypes";

export const CATALOG_SURFACE: CatalogTest[] = [
  test("Next.js __NEXT_DATA__ secrets", "Credential Exposure", "nextjsProbe.ts", [
    ["critical", "Stripe Live Secret Key in __NEXT_DATA__", "Stripe Live Secret Key in __NEXT_DATA__"],
    ["critical", "Supabase Service Role Key in __NEXT_DATA__", "Supabase Service Role Key in __NEXT_DATA__"],
    ["critical", "Private Key in __NEXT_DATA__", "Private Key in __NEXT_DATA__"],
    ["critical", "AWS Access Key ID in __NEXT_DATA__", "AWS Access Key ID in __NEXT_DATA__"],
    ["critical", "AWS Secret Access Key in __NEXT_DATA__", "AWS Secret Access Key in __NEXT_DATA__"],
    ["critical", "GitHub Token in __NEXT_DATA__", "GitHub Token in __NEXT_DATA__"],
    ["high", "SendGrid API Key in __NEXT_DATA__", "SendGrid API Key in __NEXT_DATA__"],
    ["high", "Slack Token in __NEXT_DATA__", "Slack Token in __NEXT_DATA__"],
    ["critical", "Hardcoded Database Connection String in __NEXT_DATA__", "Hardcoded Database Connection String in __NEXT_DATA__"],
  ]),
  test("known-CVE and end-of-life versions", "Outdated Software", "cveCheck.ts", [
    ["critical", "PHP end-of-life release", "is End-of-Life"],
    ["varies", "Nginx version with a known CVE", "Nginx ${d.version} — Known Vulnerability"],
    ["high", "Nginx end-of-life release cycle", "Nginx ${d.version} — End-of-Life Release Cycle"],
    ["varies", "Apache version with a known CVE", "Apache ${d.version} — Known Vulnerability"],
    ["critical", "Apache HTTPD end-of-life release branch", "Apache HTTPD ${d.version} — End-of-Life Release Branch"],
    ["critical", "Microsoft IIS 6.0 — CVE-2017-7269 WebDAV RCE", "Microsoft IIS ${d.version} — CVE-2017-7269"],
    ["varies", "Detected version matched against OSV.dev", "${target.displayName} ${target.version} — Known Vulnerability"],
  ]),
  test("dependency CVEs from an exposed manifest", "Vulnerable Components", "manifestSca.ts", [
    ["varies", "Vulnerable dependency named in an exposed manifest", "Vulnerable dependency:"],
  ]),
  test("JWT analysis", "Session Management", "jwtAnalysis.ts", [
    ["critical", "JWT Using alg:none — Signature Verification Bypass", "JWT Using alg:none — Signature Verification Bypass"],
    ["critical", "JWT Has Empty Signature — Possible Verification Bypass", "JWT Has Empty Signature — Possible Verification Bypass"],
    ["high", "JWT Token Has No Expiry (exp Claim Missing)", "JWT Token Has No Expiry (exp Claim Missing)"],
    ["high", "JWT Uses HS256 Without Expiry — Offline Brute-Force Risk", "JWT Uses HS256 Without Expiry — Offline Brute-Force Risk"],
    ["medium", "JWT Token Lifetime Excessive", "JWT Token Lifetime Is"],
    ["medium", "Sensitive Data Stored in JWT Payload", "Sensitive Data Stored in JWT Payload"],
  ]),
  test("Supabase RLS and Firebase rules", "Database Security", "supabase-probes.ts", [
    ["critical", "Supabase Service Role Key Exposed in Client-Side Code", "Supabase Service Role Key Exposed in Client-Side Code"],
    ["info", "Supabase Backend Detected", "Supabase Backend Detected"],
    ["critical", "Supabase Tables Readable Without Authentication (CVE-2025-48757)", "Supabase Tables Readable Without Authentication (CVE-2025-48757)"],
    ["high", "Supabase Tables Accessible Without Authentication (Currently Empty)", "Supabase Tables Accessible Without Authentication (Currently Empty"],
    ["critical", "Supabase Tables Accept Unauthenticated Writes", "Supabase Tables Accept Unauthenticated Writes"],
    ["info", "Supabase Backend Detected — RLS Appears Configured", "Supabase Backend Detected — RLS Appears Configured"],
    ["medium", "Supabase Storage Bucket List Exposed Without Authentication", "Supabase Storage Bucket List Exposed Without Authentication"],
    ["critical", "Firestore Security Rules Allow Unauthenticated Read Access", "Firestore Security Rules Allow Unauthenticated Read Access", "firebase-probes.ts"],
    ["info", "Firebase Backend Detected — Firestore Rules Appear Restrictive", "Firebase Backend Detected — Firestore Rules Appear Restrictive", "firebase-probes.ts"],
    ["critical", "Firebase Realtime Database Open to Unauthenticated Access", "Firebase Realtime Database Open to Unauthenticated Access", "firebase-probes.ts"],
  ]),
  test("cross-account access control", "Broken Access Control", "accessControlProbe.ts", [
    ["critical", "Broken Object-Level Authorisation (IDOR)", "Broken Object-Level Authorisation (IDOR)"],
    ["critical", "Records Enumerable by Editing the Identifier", "Records Enumerable by Editing the Identifier"],
    ["high", "Records Readable Without Signing In", "Records Readable Without Signing In"],
  ]),
  test("API endpoint testing", "API Security", "apiProbe.ts", [
    ["high", "API Endpoints Served Without Authentication", "API Endpoints Served Without Authentication"],
    ["critical", "API Records Readable by Another Account", "API Records Readable by Another Account"],
    ["critical", "Write Endpoints Reachable Without Authentication", "Write Endpoints Reachable Without Authentication"],
    ["high", "Sensitive Fields Returned by the API", "Sensitive Fields Returned by the API"],
    ["medium", "Privilege Fields Accepted in Request Bodies", "Privilege Fields Accepted in Request Bodies"],
    ["medium", "API Endpoints Without Rate Limiting", "API Endpoints Without Rate Limiting"],
    ["critical", "SQL Injection in API Parameters", "SQL Injection in API Parameters"],
  ]),
  test("public cloud storage buckets", "Cloud Storage Misconfiguration", "storageProbe.ts", [
    ["high", "Public S3 Bucket Listing", "Public S3 Bucket Listing"],
    ["high", "Public Google Cloud Storage Bucket Listing", "Public GCS Bucket Listing"],
    ["high", "Public Azure Blob Container Listing", "Public Azure Blob Container Listing"],
  ]),
  test("BaaS open data", "BaaS Misconfiguration", "baasProbes.ts", [
    ["critical", "PocketBase Collections Readable Without Authentication", "PocketBase — Unauthenticated Access to"],
    ["critical", "Appwrite Collections Readable Without Authentication", "Appwrite — Unauthenticated Document Read on"],
  ]),
  test("GraphQL introspection", "API Security", "graphqlProbe.ts", [
    ["medium", "GraphQL Introspection Enabled in Production", "GraphQL Introspection Enabled in Production"],
    ["low", "GraphQL Field Suggestions Enabled", "GraphQL Field Suggestions Enabled"],
  ]),
  test("injection", "Injection", "injectionProbe.ts", [
    ["high", "Reflected Cross-Site Scripting (XSS)", "Reflected Cross-Site Scripting (XSS)"],
    ["critical", "SQL Injection (Error-Based)", "SQL Injection (Error-Based)"],
  ]),
  test("path traversal", "Injection", "pathTraversal.ts", [
    ["critical", "Path Traversal / Local File Inclusion (LFI)", "Path Traversal / Local File Inclusion (LFI)"],
  ]),
  test("SSRF", "Server-Side Request Forgery", "ssrfProbe.ts", [
    ["critical", "Server-Side Request Forgery (SSRF)", "Server-Side Request Forgery (SSRF)"],
  ]),
  test("source map exposure", "Source Code Exposure", "sourceMaps.ts", [
    ["high", "JavaScript Source Map Exposed — Full Source Code Accessible", "JavaScript Source Map Exposed — Full Source Code Accessible"],
  ]),
  test("exposed API documentation", "API Security", "apiDocsProbe.ts", [
    ["medium", "Exposed API Documentation (OpenAPI / Swagger)", "Exposed API Documentation"],
  ]),
  test("health endpoint disclosure", "Information Disclosure", "healthEndpointProbe.ts", [
    ["info", "Health Endpoint Discloses Runtime Details", "Health Endpoint Discloses Runtime Details"],
  ]),
  test("subdomain takeover", "DNS Security", "subdomainTakeover.ts", [
    ["critical", "Dangling CNAME to a Claimable Service", "Subdomain Takeover —"],
  ]),
  test("JavaScript secret scanning", "Credential Exposure", "jsScanner.ts", [
    ["varies", "Credential found in JavaScript (34 secret patterns)", "name: f.pattern.name"],
  ]),
  test("site crawl", "Information Disclosure", "crawler.ts", [
    ["varies", "Sensitive path found on a crawled page (8 paths per page)", "name: probe.name"],
    ["varies", "Security header missing on internal routes", "Internal Route"],
    ["high", "Insecure Deserialization — serialized object in a cookie", "Insecure Deserialization Exposure (", "deserializationProbe.ts", "Insecure Deserialization"],
  ]),
  test("port scan", "Network Exposure", "recon.ts", [
    ["varies", "Unexpected open port", "Exposed ${spec.service} Service"],
  ]),
  test("SSL Labs TLS grade", "Transport Security", "worker.ts", [
    ["varies", "Weak TLS Configuration (SSL Labs grade C or below)", "Weak TLS Configuration (SSL Labs Grade"],
  ]),
];
