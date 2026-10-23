/**
 * A small ZIP reader, written separately from the writer in zipWriter.ts so the two cannot share a mistake: it finds the
 * central directory from the end of the file, reads each entry through its local header, inflates it, and checks the CRC and
 * the sizes the directory claimed.
 */
import { crc32, inflateRawSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface ReadEntry { name: string; data: Buffer; method: number }

export function readZip(buf: Buffer): ReadEntry[] {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("no end-of-central-directory record");
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  let p = buf.readUInt32LE(eocd + 16);
  if (p + cdSize !== eocd) throw new Error("central directory does not end where the end record starts");

  const out: ReadEntry[] = [];
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error("bad central directory entry");
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const compressed = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localAt = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    p += 46 + nameLen + extraLen + commentLen;

    if (buf.readUInt32LE(localAt) !== 0x04034b50) throw new Error(`bad local header for ${name}`);
    const lNameLen = buf.readUInt16LE(localAt + 26);
    const lExtraLen = buf.readUInt16LE(localAt + 28);
    const start = localAt + 30 + lNameLen + lExtraLen;
    const raw = buf.subarray(start, start + compressed);
    const data = method === 8 ? inflateRawSync(raw) : method === 0 ? Buffer.from(raw) : (() => { throw new Error(`unsupported method ${method}`); })();
    if (data.length !== size) throw new Error(`${name}: size ${data.length}, directory says ${size}`);
    if ((crc32(data) >>> 0) !== crc) throw new Error(`${name}: CRC mismatch`);
    out.push({ name, data, method });
  }
  return out;
}

/** Real archiving tools, if this machine has one: `unzip` (Linux, macOS) or `tar` (Windows ships bsdtar, which reads zip). */
export function realUnzipTool(): { name: string; list(file: string): string[]; extract(file: string, dir: string): void } | null {
  const tries: Array<{ name: string; probe: string[]; list: (f: string) => string[]; extract: (f: string, d: string) => string[] }> = [
    { name: "unzip", probe: ["-v"], list: (f) => ["-Z1", f], extract: (f, d) => ["-q", f, "-d", d] },
    { name: "tar", probe: ["--version"], list: (f) => ["-tf", f], extract: (f, d) => ["-xf", f, "-C", d] },
  ];
  for (const t of tries) {
    try {
      const v = execFileSync(t.name, t.probe, { stdio: ["ignore", "pipe", "ignore"] }).toString();
      // GNU tar cannot read zip; bsdtar says so in its version line.
      if (t.name === "tar" && !/bsdtar/i.test(v)) continue;
      return {
        name: t.name,
        list: (file) => execFileSync(t.name, t.list(file), { stdio: ["ignore", "pipe", "pipe"] }).toString().split(/\r?\n/).filter(Boolean),
        extract: (file, dir) => { execFileSync(t.name, t.extract(file, dir), { stdio: ["ignore", "pipe", "pipe"] }); },
      };
    } catch { /* not installed */ }
  }
  return null;
}

/** Writes `bytes` to a temp file for a tool to read, and removes it afterwards. */
export function withTempFile<T>(bytes: Buffer, fn: (file: string, dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "secscan-zip-"));
  try {
    const file = join(dir, "pack.zip");
    writeFileSync(file, bytes);
    return fn(file, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
