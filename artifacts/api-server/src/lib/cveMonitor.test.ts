import { describe, it, expect } from "vitest";
import {
  bareTechName,
  compareVersions,
  describeAffected,
  detectedVersion,
  matchCvesToTechnologies,
  parseNvdCve,
  versionInRange,
  type NvdCve,
} from "./cveMonitor";

/**
 * The monitor used to match CVEs by searching their prose for a keyword, with no version
 * check. Measured on three real hours of NVD data (2026-09-24): one CVE mentioned "nginx"
 * and none affected it, so every nginx site would have been alerted and rescanned for
 * nothing. "php" is worse: it appears in countless CVEs about unrelated PHP applications.
 *
 * These tests use real NVD records, trimmed, so they check the actual data shape.
 */

// CVE-2021-23017 as NVD serves it (configurations trimmed to three nodes).
const NGINX_RAW = {
  id: "CVE-2021-23017",
  vulnStatus: "Modified",
  published: "2021-06-01T13:15:07.853",
  descriptions: [{ lang: "en", value: "A security issue in nginx resolver was identified, which might allow an attacker to cause 1-byte memory overwrite by using a specially crafted DNS response." }],
  metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.7, baseSeverity: "HIGH" } }] },
  configurations: [
    { nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionStartIncluding: "0.6.18", versionEndExcluding: "1.20.1" }] }] },
    { nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:openresty:openresty:*:*:*:*:*:*:*:*", versionEndExcluding: "1.19.3.2" }] }] },
    { nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*" }] }] },
  ],
};

// CVE-2024-4577 (PHP-CGI argument injection), three of its PHP ranges.
const PHP_RAW = {
  id: "CVE-2024-4577",
  vulnStatus: "Analyzed",
  published: "2024-06-09T20:15:09.550",
  descriptions: [{ lang: "en", value: "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows…" }],
  metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
  configurations: [
    {
      nodes: [
        {
          cpeMatch: [
            { vulnerable: true, criteria: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", versionStartIncluding: "8.1.0", versionEndExcluding: "8.1.29" },
            { vulnerable: true, criteria: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", versionStartIncluding: "8.2.0", versionEndExcluding: "8.2.20" },
            { vulnerable: true, criteria: "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", versionStartIncluding: "8.3.0", versionEndExcluding: "8.3.8" },
          ],
        },
        // The platform the flaw needs, not a vulnerable product.
        { cpeMatch: [{ vulnerable: false, criteria: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*" }] },
      ],
    },
  ],
};

const NGINX = parseNvdCve(NGINX_RAW);
const PHP_CGI = parseNvdCve(PHP_RAW);

/** The keyword false positive, in the real shape: prose mentions nginx, product data does not. */
const MENTIONS_NGINX: NvdCve = parseNvdCve({
  id: "CVE-2026-99001",
  vulnStatus: "Analyzed",
  published: "2026-09-24T10:00:00.000",
  descriptions: [{ lang: "en", value: "SomeCMS before 4.2, when deployed behind nginx, allows stored XSS via the admin.php comment form." }],
  metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.1, baseSeverity: "HIGH" } }] },
  configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:somecms:somecms:*:*:*:*:*:*:*:*", versionEndExcluding: "4.2" }] }] }],
});

/** Not analysed yet: NVD has no product data, only prose. */
const AWAITING: NvdCve = parseNvdCve({
  id: "CVE-2026-99002",
  vulnStatus: "Awaiting Analysis",
  published: "2026-09-24T11:00:00.000",
  descriptions: [{ lang: "en", value: "A heap overflow in nginx 1.27 HTTP/3 handling." }],
  metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.1, baseSeverity: "CRITICAL" } }] },
});

describe("parseNvdCve", () => {
  it("keeps vulnerable application products with their ranges", () => {
    expect(NGINX.products).toEqual(
      expect.arrayContaining([
        { product: "f5:nginx", exactVersion: null, startIncluding: "0.6.18", endExcluding: "1.20.1" },
        { product: "openresty:openresty", exactVersion: null, endExcluding: "1.19.3.2" },
      ]),
    );
  });

  it("drops operating-system entries and platform conditions", () => {
    expect(NGINX.products.some((p) => p.product.startsWith("fedoraproject"))).toBe(false);
    expect(PHP_CGI.products.some((p) => p.product.includes("windows"))).toBe(false);
    expect(PHP_CGI.products).toHaveLength(3);
  });

  it("reads severity, score and status", () => {
    expect(PHP_CGI.severity).toBe("CRITICAL");
    expect(PHP_CGI.cvssScore).toBe(9.8);
    expect(AWAITING.status).toBe("Awaiting Analysis");
    expect(AWAITING.products).toEqual([]);
  });
});

describe("versions", () => {
  it("reads the version the scanner appended, in every shape it produces", () => {
    expect(detectedVersion("Nginx 1.18.0")).toBe("1.18.0");
    expect(detectedVersion("Nginx v1.18.0")).toBe("1.18.0");
    expect(detectedVersion("Nginx 1.18.0-1")).toBe("1.18.0-1");
    expect(detectedVersion("Nginx")).toBeNull();
    expect(detectedVersion("Ruby on Rails")).toBeNull();
  });

  it("strips only a trailing version from the name", () => {
    expect(bareTechName("Ruby on Rails 7.1.3")).toBe("Ruby on Rails");
    expect(bareTechName("AWS CloudFront")).toBe("AWS CloudFront");
  });

  it("compares numerically, not as text", () => {
    expect(compareVersions("1.9.0", "1.10.0")).toBeLessThan(0);
    expect(compareVersions("1.19.3.2", "1.19.3")).toBeGreaterThan(0);
    expect(compareVersions("8.1", "8.1.0")).toBe(0);
    expect(compareVersions("1.18.0-1ubuntu1", "1.18.0")).toBe(0);
    expect(compareVersions("v2.0", "1.99")).toBeGreaterThan(0);
  });

  it("applies each kind of range bound", () => {
    const r = { product: "f5:nginx", exactVersion: null, startIncluding: "0.6.18", endExcluding: "1.20.1" };
    expect(versionInRange("1.18.0", r)).toBe(true);
    expect(versionInRange("0.6.18", r)).toBe(true);
    expect(versionInRange("1.20.1", r)).toBe(false);
    expect(versionInRange("0.6.17", r)).toBe(false);
    expect(versionInRange("5.0", { product: "x:y", exactVersion: null, startExcluding: "5.0", endIncluding: "6.0" })).toBe(false);
    expect(versionInRange("6.0", { product: "x:y", exactVersion: null, startExcluding: "5.0", endIncluding: "6.0" })).toBe(true);
    expect(versionInRange("2.4.49", { product: "x:y", exactVersion: "2.4.49" })).toBe(true);
    expect(versionInRange("2.4.50", { product: "x:y", exactVersion: "2.4.49" })).toBe(false);
  });
});

describe("matchCvesToTechnologies", () => {
  it("does not match a CVE that only mentions the software in its prose (the old false positive)", () => {
    expect(matchCvesToTechnologies(["Nginx 1.18.0", "PHP 8.1.2"], [MENTIONS_NGINX])).toEqual([]);
    expect(matchCvesToTechnologies(["Nginx"], [MENTIONS_NGINX])).toEqual([]);
  });

  it("marks a detected version inside the range as affected", () => {
    const [hit] = matchCvesToTechnologies(["Nginx 1.18.0"], [NGINX]);
    expect(hit).toMatchObject({ matchedTech: "Nginx 1.18.0", basis: "affected" });
    expect(hit!.cve.id).toBe("CVE-2021-23017");
  });

  it("stays quiet when the detected version is outside every range", () => {
    expect(matchCvesToTechnologies(["Nginx 1.24.0"], [NGINX])).toEqual([]);
    expect(matchCvesToTechnologies(["PHP 8.3.9"], [PHP_CGI])).toEqual([]);
    expect(matchCvesToTechnologies(["PHP 7.4.33"], [PHP_CGI])).toEqual([]);
  });

  it("finds the right one of several ranges", () => {
    expect(matchCvesToTechnologies(["PHP 8.2.19"], [PHP_CGI])[0]?.basis).toBe("affected");
    expect(matchCvesToTechnologies(["PHP 8.2.20"], [PHP_CGI])).toEqual([]);
  });

  it("matches a product listed under another vendor", () => {
    expect(matchCvesToTechnologies(["OpenResty 1.19.3.1"], [NGINX])[0]?.basis).toBe("affected");
  });

  it("without a version, alerts only on HIGH or CRITICAL, and says the version is unknown", () => {
    const [hit] = matchCvesToTechnologies(["PHP"], [PHP_CGI]);
    expect(hit?.basis).toBe("unconfirmed");
    const medium = { ...NGINX, severity: "MEDIUM" };
    expect(matchCvesToTechnologies(["Nginx"], [medium])).toEqual([]);
  });

  it("cannot match a CVE NVD has not analysed yet (it is picked up when NVD adds product data)", () => {
    expect(matchCvesToTechnologies(["Nginx 1.27.0", "Nginx"], [AWAITING])).toEqual([]);
  });

  it("ignores rejected CVEs", () => {
    expect(matchCvesToTechnologies(["Nginx 1.18.0"], [{ ...NGINX, status: "Rejected" }])).toEqual([]);
  });

  it("does not match hosting platforms at all", () => {
    const cfCve = parseNvdCve({
      id: "CVE-2026-99003",
      vulnStatus: "Analyzed",
      published: "2026-09-24T12:00:00.000",
      descriptions: [{ lang: "en", value: "Cloudflare WARP client for Windows allows local privilege escalation." }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.8, baseSeverity: "HIGH" } }] },
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:cloudflare:warp:*:*:*:*:*:windows:*:*", versionEndExcluding: "2024.1" }] }] }],
    });
    expect(matchCvesToTechnologies(["Cloudflare", "Railway", "Vercel"], [cfCve])).toEqual([]);
  });

  it("reports each CVE once per technology, and nothing for unknown software", () => {
    expect(matchCvesToTechnologies(["Nginx 1.18.0", "Nginx 1.18.0"], [NGINX])).toHaveLength(1);
    expect(matchCvesToTechnologies(["Tailwind CSS"], [NGINX])).toEqual([]);
    expect(matchCvesToTechnologies([], [NGINX])).toEqual([]);
  });
});

describe("the product table", () => {
  it("matches Joomla, whose NVD product name contains an escaped '!'", () => {
    // Criteria string copied from CVE-2023-23752.
    const joomla = parseNvdCve({
      id: "CVE-2023-23752",
      vulnStatus: "Analyzed",
      published: "2023-02-16T17:15:09.673",
      descriptions: [{ lang: "en", value: "An improper access check allows unauthorized access to webservice endpoints." }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 5.3, baseSeverity: "MEDIUM" } }] },
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*", versionStartIncluding: "4.0.0", versionEndExcluding: "4.2.8" }] }] }],
    });
    expect(matchCvesToTechnologies(["Joomla 4.2.7"], [joomla])[0]?.basis).toBe("affected");
    expect(matchCvesToTechnologies(["Joomla 4.2.8"], [joomla])).toEqual([]);
  });
});

describe("describeAffected: how the alert reads", () => {
  it("never words an unconfirmed match like a confirmed one", () => {
    expect(describeAffected({ matchedTech: "Nginx 1.18.0", basis: "affected" })).toBe(
      "Nginx 1.18.0 (detected version is in the affected range)",
    );
    expect(describeAffected({ matchedTech: "PHP", basis: "unconfirmed" })).toBe(
      "PHP (version not detected; check whether yours is affected)",
    );
  });
});
