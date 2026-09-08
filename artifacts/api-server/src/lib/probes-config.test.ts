import { describe, it, expect } from "vitest";
import { SENSITIVE_PATHS } from "./probes-data.js";

const cfg = SENSITIVE_PATHS.find((p) => p.path === "/config.json")!;
const json = "application/json";

describe("/config.json — a public SPA bootstrap config is not an exposure", () => {
  it("does NOT flag a frontend config of endpoints and publishable keys", () => {
    // kraken.com's real /config.json shape: API URLs, websocket endpoints,
    // LaunchDarkly client ids, and publishable SDK keys. All public by design.
    const body = JSON.stringify({
      api: "https://api.kraken.com",
      spot_websocket: "wss://ws.kraken.com",
      private_websocket_v1: "wss://ws-auth.kraken.com",
      accounts_ld_cli_id: "5f2b1c9d4e",
      firebase_apiKey: "AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8",
      braze: { apiKey: "1a2b3c4d-5e6f-7a8b-9c0d" },
    });
    expect(cfg.validate(body, json)).toBe(false);
  });

  it("still flags a config carrying a real secret", () => {
    const body = JSON.stringify({
      api: "https://api.example.com",
      db_password: "s3cr3t-prod-passw0rd",
    });
    expect(cfg.validate(body, json)).toBe(true);
  });

  it("still flags a connection string", () => {
    const body = JSON.stringify({ connectionString: "postgres://u:p@db.internal:5432/app" });
    expect(cfg.validate(body, json)).toBe(true);
  });

  it("still flags a client_secret", () => {
    expect(cfg.validate(JSON.stringify({ client_secret: "GOCSPX-abcdefghijklmnop" }), json)).toBe(true);
  });

  it("ignores an empty or placeholder secret value", () => {
    expect(cfg.validate(JSON.stringify({ password: "" }), json)).toBe(false);
    expect(cfg.validate(JSON.stringify({ secret: "x" }), json)).toBe(false);
  });

  it("still refuses the SPA HTML shell", () => {
    expect(cfg.validate("<!doctype html><html></html>", "text/html")).toBe(false);
  });
});
