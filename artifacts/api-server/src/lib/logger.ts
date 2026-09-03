import pino from "pino";

const isProduction = process.env.NODE_ENV === "production";

export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  redact: [
    "req.headers.authorization",
    "req.headers.cookie",
    "res.headers['set-cookie']",

    // Scan credentials. These arrive in a request body and are carried through
    // the worker, so a stray log of the object — or of an error holding it —
    // would otherwise write a customer's password to disk. Wildcards cover the
    // nesting depths the value actually appears at.
    "credentials",
    "*.credentials",
    "*.*.credentials",
    "password",
    "*.password",
    "*.*.password",
    "currentPassword",
    "*.currentPassword",
    "newPassword",
    "*.newPassword",
    "bearerToken",
    "*.bearerToken",
    "cookie",
    "*.cookie",
    "credentialsEncrypted",
    "*.credentialsEncrypted",
  ],
  ...(isProduction
    ? {}
    : {
        transport: {
          target: "pino-pretty",
          options: { colorize: true },
        },
      }),
});
