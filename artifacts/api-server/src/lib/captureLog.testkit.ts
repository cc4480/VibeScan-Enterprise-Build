/**
 * A real pino logger whose output is captured, for tests of code that takes a logger. What the code logged is read back
 * from the records the logger really wrote (level, message and fields), rather than from a recording stand-in.
 */
import { Writable } from "node:stream";
import pino from "pino";

export type LogRecord = Record<string, unknown> & { level: number; msg?: string };
export type LevelName = "debug" | "info" | "warn" | "error";

export interface CapturedLog {
  log: pino.Logger;
  /** Every record written, oldest first. */
  lines: LogRecord[];
  /** The records written at this level. */
  at(level: LevelName): LogRecord[];
}

/** The fields of a record, without pino's level and message. */
export function fieldsOf(record: LogRecord): Record<string, unknown> {
  const { level: _level, msg: _msg, ...rest } = record;
  return rest;
}

export function capturedLog(level: LevelName = "debug"): CapturedLog {
  const lines: LogRecord[] = [];
  const log = pino(
    { level, base: null, timestamp: false },
    new Writable({ write(chunk, _enc, cb) { lines.push(JSON.parse(String(chunk))); cb(); } }),
  );
  return { log, lines, at: (name) => lines.filter((l) => l.level === pino.levels.values[name]) };
}
