import { describe, it, expect } from "vitest";
import { labelEdgePorts, EDGE_PORT_LABEL, type PortEntry } from "./recon";

const ports: PortEntry[] = [
  { port: 80, service: "HTTP", banner: null },
  { port: 443, service: "HTTPS", banner: null },
  { port: 8080, service: "Alt HTTP / Proxy", banner: null },
  { port: 8443, service: "Alt HTTPS", banner: null },
];

describe("labelEdgePorts", () => {
  it("labels every open port as Cloudflare's edge when the site resolves to a Cloudflare address", () => {
    const out = labelEdgePorts(ports, "104.21.5.10");
    expect(out.map((p) => p.service)).toEqual([
      `HTTP${EDGE_PORT_LABEL}`,
      `HTTPS${EDGE_PORT_LABEL}`,
      `Alt HTTP / Proxy${EDGE_PORT_LABEL}`,
      `Alt HTTPS${EDGE_PORT_LABEL}`,
    ]);
    expect(out.map((p) => p.port)).toEqual([80, 443, 8080, 8443]);
  });

  it("leaves the ports of a site that is not behind Cloudflare exactly as found", () => {
    expect(labelEdgePorts(ports, "93.184.216.34")).toEqual(ports);
  });

  it("leaves them alone when the address is unknown", () => {
    expect(labelEdgePorts(ports, null)).toEqual(ports);
  });

  it("does not mutate the ports it was given", () => {
    labelEdgePorts(ports, "104.21.5.10");
    expect(ports[2]?.service).toBe("Alt HTTP / Proxy");
  });
});
