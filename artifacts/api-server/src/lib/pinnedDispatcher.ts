/**
 * Connects the scanner's sockets only to addresses it has just vetted.
 *
 * checkUrlSafe resolves a name and judges the answer, but `fetch` then resolves the name again
 * on its own, so a DNS server that answers a public address first and 127.0.0.1 second (a
 * rebinding record) passes the check and is then connected to. Here the check and the
 * connection share one lookup: the address the socket opens to is the address that was judged.
 */
import dns from "node:dns";
import { Agent } from "undici";
import { isPrivateAddress, privateTargetsAllowed } from "./ssrfGuard";

type LookupAddress = { address: string; family: number };
type LookupCallback = (err: NodeJS.ErrnoException | null, address?: string | LookupAddress[], family?: number) => void;

/**
 * A `dns.lookup` stand-in that refuses a name if any answer is private or local.
 * `honourOptOut` lets ALLOW_PRIVATE_SCAN_TARGETS through: right for scan targets, wrong for
 * anything else (see strictDispatcher).
 */
function lookupWith(honourOptOut: boolean) {
  return (
    hostname: string,
    options: { all?: boolean; family?: number | string } | LookupCallback,
    callback?: LookupCallback,
  ): void => vet(hostname, options, callback, honourOptOut);
}

function vet(
  hostname: string,
  options: { all?: boolean; family?: number | string } | LookupCallback,
  callback: LookupCallback | undefined,
  honourOptOut: boolean,
): void {
  const cb = (typeof options === "function" ? options : callback) as LookupCallback;
  const opts = typeof options === "function" ? {} : options;

  dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return cb(err);
    if (!(honourOptOut && privateTargetsAllowed()) && (addresses.length === 0 || addresses.some((a) => isPrivateAddress(a.address)))) {
      const blocked: NodeJS.ErrnoException = new Error("blocked target address: resolves to a private or local address");
      blocked.code = "ESSRFBLOCKED";
      return cb(blocked);
    }
    const wanted = opts.family === 4 || opts.family === "IPv4" ? 4 : opts.family === 6 || opts.family === "IPv6" ? 6 : 0;
    const usable = wanted ? addresses.filter((a) => a.family === wanted) : addresses;
    if (usable.length === 0) {
      const none: NodeJS.ErrnoException = new Error(`no address for ${hostname}`);
      none.code = "ENOTFOUND";
      return cb(none);
    }
    if (opts.all) return cb(null, usable);
    cb(null, usable[0]!.address, usable[0]!.family);
  });
}

export const vettedLookup = lookupWith(true);

/**
 * The same vetted lookup for raw sockets (net.connect), with no opt-out. Used for mail exchangers, which are named by
 * DNS rather than by the user, so ALLOW_PRIVATE_SCAN_TARGETS does not reach them.
 */
export const strictLookup = lookupWith(false) as never;

/**
 * For requests to a host a user named that is not a scan target (webhooks, domain verification).
 * Private addresses are refused whatever ALLOW_PRIVATE_SCAN_TARGETS says: a self-hoster who opts
 * in to scanning their own network has not opted in to having webhooks post there.
 */
export const strictDispatcher = new Agent({ connect: { lookup: lookupWith(false) as never } });

/** Shared by every request the scanner makes at a target. */
export const scanDispatcher = new Agent({ connect: { lookup: vettedLookup as never } });
