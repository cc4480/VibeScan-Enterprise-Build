/**
 * A ZIP file written in memory, with nothing but Node's own zlib.
 *
 * Deterministic on purpose: the same files and the same date give byte-for-byte the same archive, so an evidence pack can be
 * regenerated and compared, and a hash of it means something. Entries are deflated when that makes them smaller and stored
 * otherwise. No ZIP64: a pack is a few hundred kilobytes, and a larger one is refused rather than written wrongly.
 */
import { crc32, deflateRawSync } from "node:zlib";

export interface ZipEntry { name: string; data: Buffer }

const MAX_BYTES = 0xffff_0000;
const MAX_ENTRIES = 0xfff0;

/** MS-DOS date and time fields, in UTC. ZIP cannot represent a year before 1980. */
function dosDateTime(d: Date): { date: number; time: number } {
  const year = Math.max(1980, d.getUTCFullYear());
  return {
    date: ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate(),
    time: (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | Math.floor(d.getUTCSeconds() / 2),
  };
}

export function zip(entries: ZipEntry[], when: Date): Buffer {
  if (entries.length > MAX_ENTRIES) throw new Error("too many files for a zip");
  const { date, time } = dosDateTime(when);
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    // Names are forward-slash paths with no way out of the archive.
    if (!entry.name || entry.name.startsWith("/") || entry.name.includes("..") || entry.name.includes("\\") || /[\u0000-\u001f]/.test(entry.name)) {
      throw new Error(`unsafe zip entry name: ${JSON.stringify(entry.name)}`);
    }
    const name = Buffer.from(entry.name, "utf8");
    const deflated = deflateRawSync(entry.data, { level: 9 });
    const useDeflate = deflated.length < entry.data.length;
    const body = useDeflate ? deflated : entry.data;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(entry.data) >>> 0;
    const flags = 0x0800; // file names are UTF-8

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(0x031e, 4); // made by: Unix, spec 3.0
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(flags, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt16LE(time, 12);
    cd.writeUInt16LE(date, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(body.length, 20);
    cd.writeUInt32LE(entry.data.length, 24);
    cd.writeUInt16LE(name.length, 28);
    cd.writeUInt32LE((0o100644 << 16) >>> 0, 38); // external attributes: a regular file, rw-r--r--
    cd.writeUInt32LE(offset, 42);

    parts.push(local, name, body);
    central.push(cd, name);
    offset += local.length + name.length + body.length;
    if (offset > MAX_BYTES) throw new Error("zip too large");
  }

  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  const out = Buffer.concat([...parts, centralBuf, end]);
  if (out.length > MAX_BYTES) throw new Error("zip too large");
  return out;
}
