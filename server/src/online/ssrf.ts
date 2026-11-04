import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { OnlineError } from "./errors.js";
import { ONLINE_DNS_TIMEOUT_MS, ONLINE_MAX_URL_CHARS } from "./limits.js";

// Fail-closed SSRF guard. Every URL the fetcher touches — the start URL and
// every redirect target — passes through here, and every hostname is resolved
// and checked immediately before use so a stale verdict is never trusted.

// ---- IPv4 ----

function parseIPv4(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

// [base, prefixLength] — non-global IPv4 ranges that must never be fetched.
const BLOCKED_V4: Array<[number, number]> = [
  [0x00000000, 8], // software scope ("this network")
  [0x0a000000, 8], // private
  [0x64400000, 10], // carrier-grade NAT
  [0x7f000000, 8], // loopback
  [0xa9fe0000, 16], // link-local (covers cloud metadata 169.254.169.254)
  [0xac100000, 12], // private
  [0xc0000000, 24], // IETF protocol assignments
  [0xc0000200, 24], // documentation TEST-NET-1
  [0xc0586300, 24], // 6to4 relay (deprecated)
  [0xc0a80000, 16], // private
  [0xc6120000, 15], // benchmarking
  [0xc6336400, 24], // documentation TEST-NET-2
  [0xcb007100, 24], // documentation TEST-NET-3
  [0xe0000000, 4], // multicast
  [0xf0000000, 4], // reserved + broadcast
];

function isBlockedIPv4(ip: string): boolean {
  const value = parseIPv4(ip);
  if (value === null) return true;
  for (const [base, prefix] of BLOCKED_V4) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    if ((value & mask) >>> 0 === base) return true;
  }
  return false;
}

// ---- IPv6 ----

function parseIPv6(ip: string): Uint16Array | null {
  // Split on "::" (at most one occurrence) and expand.
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] === "" ? [] : halves[0]!.split(":");
  const tail = halves.length === 2 ? (halves[1] === "" ? [] : halves[1]!.split(":")) : [];
  // An embedded trailing IPv4 address counts as two hextets.
  const expand = (groups: string[]): number[] | null => {
    const out: number[] = [];
    for (let i = 0; i < groups.length; i += 1) {
      const g = groups[i]!;
      if (g.includes(".")) {
        if (i !== groups.length - 1) return null;
        const v4 = parseIPv4(g);
        if (v4 === null) return null;
        out.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
        out.push(Number.parseInt(g, 16));
      }
    }
    return out;
  };
  const headNums = expand(head);
  const tailNums = expand(tail);
  if (!headNums || !tailNums) return null;
  const zeros = 8 - headNums.length - tailNums.length;
  if (halves.length === 1 ? zeros !== 0 : zeros < 0) return null;
  return new Uint16Array([...headNums, ...new Array(Math.max(0, zeros)).fill(0), ...tailNums]);
}

function v6PrefixMatches(addr: Uint16Array, prefix: number[], bits: number): boolean {
  let remaining = bits;
  for (let i = 0; i < prefix.length && remaining > 0; i += 1) {
    const take = Math.min(16, remaining);
    const mask = take === 16 ? 0xffff : (0xffff << (16 - take)) & 0xffff;
    if ((addr[i]! & mask) !== (prefix[i]! & mask)) return false;
    remaining -= take;
  }
  return true;
}

function isBlockedIPv6(ip: string): boolean {
  const addr = parseIPv6(ip);
  if (!addr) return true;
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d): judge the
  // embedded IPv4 address, which also catches :: and ::1.
  if (addr[0] === 0 && addr[1] === 0 && addr[2] === 0 && addr[3] === 0 && addr[4] === 0) {
    if (addr[5] === 0 || addr[5] === 0xffff) {
      const v4 = `${addr[6]! >>> 8}.${addr[6]! & 0xff}.${addr[7]! >>> 8}.${addr[7]! & 0xff}`;
      return isBlockedIPv4(v4);
    }
  }
  if (v6PrefixMatches(addr, [0x64, 0xff9b, 0, 0, 0, 0], 96)) {
    // NAT64 Well-Known Prefix embeds a global-or-not IPv4 address.
    const v4 = `${addr[6]! >>> 8}.${addr[6]! & 0xff}.${addr[7]! >>> 8}.${addr[7]! & 0xff}`;
    return isBlockedIPv4(v4);
  }
  const blocked: Array<[number[], number]> = [
    [[0x100, 0, 0, 0], 64], // discard
    [[0x2001, 0, 0, 0], 32], // Teredo embeds an obfuscated IPv4 address: block all
    [[0x2002, 0, 0, 0], 16], // 6to4 embeds an IPv4 address: block all
    [[0x2001, 0xdb8, 0, 0], 32], // documentation
    [[0xfc00, 0, 0, 0], 7], // unique-local
    [[0xfe80, 0, 0, 0], 10], // link-local
    [[0xff00, 0, 0, 0], 8], // multicast
  ];
  return blocked.some(([prefix, bits]) => v6PrefixMatches(addr, prefix, bits));
}

export function isBlockedIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isBlockedIPv4(ip);
  if (family === 6) return isBlockedIPv6(ip);
  return true;
}

// ---- URLs ----

export function validatePublicUrl(raw: string): URL {
  if (typeof raw !== "string") {
    throw new OnlineError("invalid-url", "URL must be a string");
  }
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new OnlineError("invalid-url", "URL is empty");
  }
  if (trimmed.length > ONLINE_MAX_URL_CHARS) {
    throw new OnlineError("invalid-url", `URL exceeds ${ONLINE_MAX_URL_CHARS} characters`);
  }
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new OnlineError("invalid-url", "not a valid absolute URL (include http:// or https://)");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new OnlineError("invalid-url", "only http:// and https:// URLs are supported");
  }
  if (url.username !== "" || url.password !== "") {
    throw new OnlineError("invalid-url", "credentials in URLs are not allowed");
  }
  if (url.hostname === "") {
    throw new OnlineError("invalid-url", "URL has no hostname");
  }
  return url;
}

export function validateRedirectTarget(current: URL, location: string): URL {
  let next: URL;
  try {
    next = new URL(location, current);
  } catch {
    throw new OnlineError("fetch-failed", "server returned an invalid redirect target");
  }
  return validatePublicUrl(next.href);
}

// ---- DNS ----

export type HostResolver = (host: string) => Promise<string[]>;

async function defaultResolver(host: string): Promise<string[]> {
  const records = await lookup(host, { all: true });
  return records.map((r) => r.address);
}

function isDnsName(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  // A trailing dot is legal; strip it for label checks.
  const bare = host.endsWith(".") ? host.slice(0, -1) : host;
  if (bare.length === 0) return false;
  return bare.split(".").every((label) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

// Resolves a hostname and returns EVERY resolved address, rejecting the
// host unless all of them are public IPs. Callers that go on to connect
// MUST use only the returned addresses (see pinnedFetch.ts, which pins the
// connection through a custom lookup so no second DNS resolution happens).
// That closes the DNS-rebinding race: there is no fetch-time lookup left
// for an attacker to win. Callers must invoke this immediately before each
// connection (including every redirect hop) and never cache the verdict.
export async function resolveValidatedAddresses(
  hostname: string,
  resolver: HostResolver = defaultResolver,
  dnsTimeoutMs: number = ONLINE_DNS_TIMEOUT_MS
): Promise<string[]> {
  let name = hostname.endsWith(".") && hostname.length > 1 ? hostname.slice(0, -1) : hostname;
  // URL.hostnames keep IPv6 literals bracketed ("[::1]"); unwrap one pair so
  // the IP classifier sees the real address. Anything bracketed that is not
  // a valid IP fails closed instead of falling through to DNS.
  if (name.startsWith("[") && name.endsWith("]")) {
    const inner = name.slice(1, -1);
    if (isIP(inner) === 0) {
      throw new OnlineError("invalid-url", "hostname is not valid");
    }
    name = inner;
  }
  if (isIP(name) !== 0) {
    if (isBlockedIp(name)) {
      throw new OnlineError("blocked-host", "that address is not a public web host");
    }
    return [name];
  }
  if (!isDnsName(name)) {
    throw new OnlineError("invalid-url", "hostname is not valid");
  }
  let addresses: string[];
  let dnsTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    addresses = await Promise.race([
      resolver(name),
      new Promise<never>((_, reject) => {
        dnsTimer = setTimeout(() => reject(new Error("dns timeout")), dnsTimeoutMs);
      }),
    ]);
  } catch {
    throw new OnlineError("dns-failed", `could not resolve host "${name.slice(0, 100)}"`);
  } finally {
    if (dnsTimer !== undefined) clearTimeout(dnsTimer);
  }
  if (addresses.length === 0) {
    throw new OnlineError("dns-failed", `host "${name.slice(0, 100)}" has no addresses`);
  }
  if (addresses.some((addr) => isBlockedIp(addr))) {
    throw new OnlineError("blocked-host", "that host does not resolve to a public address");
  }
  return addresses;
}

// Validation-only wrapper kept for callers that never connect.
export async function resolveAndValidateHost(
  hostname: string,
  resolver: HostResolver = defaultResolver,
  dnsTimeoutMs: number = ONLINE_DNS_TIMEOUT_MS
): Promise<void> {
  await resolveValidatedAddresses(hostname, resolver, dnsTimeoutMs);
}
