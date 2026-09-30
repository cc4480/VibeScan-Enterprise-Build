/**
 * Data module: sensitive file/path probes used by probes.ts active checks.
 * The list itself is split by topic across probes-data-*.ts.
 */

import { SENSITIVE_PATHS_VCS_ENV_CMS } from "./probes-data-vcs";
import { SENSITIVE_PATHS_CONFIG } from "./probes-data-config";
export { isSecretBearingConfigJson } from "./probes-data-config";
import { SENSITIVE_PATHS_INFRA } from "./probes-data-infra";
import { SENSITIVE_PATHS_SERVER } from "./probes-data-server";
import type { ScanVulnerability } from "./scanner";

export interface SensitivePath {
  path: string;
  name: string;
  severity: ScanVulnerability["severity"];
  cweId: string;
  cvssScore?: number;
  category: string;
  description: string;
  solution: string;
  validate: (body: string, contentType: string) => boolean;
  /**
   * Set when the file's genuine exposed content is itself an HTML document —
   * phpinfo output, an Apache status page, an admin login form. For every other
   * path a full HTML document is the SPA/catch-all shell, not the file, and the
   * probe layer suppresses it before validate runs. Without this exemption that
   * suppression would also hide a real phpinfo page. See probes.ts.
   */
  servesHtml?: boolean;
}

export const SENSITIVE_PATHS: SensitivePath[] = [
  ...SENSITIVE_PATHS_VCS_ENV_CMS,
  ...SENSITIVE_PATHS_CONFIG,
  ...SENSITIVE_PATHS_INFRA,
  ...SENSITIVE_PATHS_SERVER,
];
