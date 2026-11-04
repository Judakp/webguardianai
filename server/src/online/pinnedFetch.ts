import {
  request as httpRequest,
  type ClientRequest,
  type IncomingMessage,
  type RequestOptions,
} from "node:http";
import { request as httpsRequest, type RequestOptions as HttpsRequestOptions } from "node:https";
import { isIP } from "node:net";
import { Readable } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";

// Production HTTP connector with validated-IP pinning.
//
// Problem: a validate-then-fetch flow that re-resolves the hostname at
// connect time has a DNS-rebinding race — the address the fetcher connects
// to can differ from the address the validator approved. This module closes
// that race: the caller passes the exact public addresses that SSRF
// validation approved, and the connection is pinned to one of them through
// a custom `lookup` function, so no second DNS resolution ever happens.
//
// TLS hostname verification stays fully intact: only the TCP destination
// is pinned. SNI (`servername`) and certificate identity checks both use
// the original hostname, exactly as a normal HTTPS client would.
// Connections never reuse sockets (`agent: false`), so a pooled socket
// from an earlier hop can never bypass per-hop validation.

export interface PinnedFetchInit {
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") && host.length > 2
    ? host.slice(1, -1)
    : host;
}

// Builds a `lookup` function that ignores DNS entirely and always returns
// the first address from the validated list. The list MUST contain only
// addresses that already passed SSRF validation; this function merely
// filters out malformed entries and fails closed when nothing is usable.
export function createPinnedLookup(
  addresses: string[]
): NonNullable<RequestOptions["lookup"]> {
  const pinned = addresses.filter((a) => isIP(a) === 4 || isIP(a) === 6);
  return (_hostname, options, callback) => {
    // Node may invoke custom lookup with `all: true` (notably when its
    // automatic address-family selection is enabled). In that mode the
    // callback MUST receive an array of { address, family }, not the legacy
    // (address, family) pair. Returning the wrong shape can surface as
    // ERR_INVALID_IP_ADDRESS even though the IP itself is valid.
    const requestedFamily = typeof options === "number" ? options : options.family ?? 0;
    const candidates = pinned.filter(
      (address) => requestedFamily === 0 || isIP(address) === requestedFamily
    );
    if (candidates.length === 0) {
      callback(Object.assign(new Error("no compatible validated address"), { code: "ENOTFOUND" }), "", 0);
      return;
    }
    if (typeof options === "object" && options !== null && options.all) {
      callback(
        null,
        candidates.map((address) => ({ address, family: isIP(address) }))
      );
      return;
    }
    const pick = candidates[0]!;
    callback(null, pick, isIP(pick));
  };
}

// Socket errors that mean "this address did not answer" and justify trying
// the next validated address. Anything else (TLS/certificate errors,
// HTTP-level failures, aborts) is definitive for this hostname.
const RETRYABLE_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "EPIPE",
]);

export function isRetryableConnectionError(err: unknown): boolean {
  const code =
    typeof err === "object" && err !== null && "code" in err
      ? (err as { code?: unknown }).code
      : undefined;
  return typeof code === "string" && RETRYABLE_CODES.has(code);
}

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error("request aborted");
}

// Wraps a connector error so fetchSite's diagnostics (`cause.code`) keep
// working while the original error stays available for inspection.
function wrapError(message: string, err: unknown): Error {
  return new Error(message, { cause: err });
}

// Decodes the body transfer codings a server may apply (gzip, deflate,
// br). Unknown codings pass through raw: extraction downstream is
// best-effort, and a passthrough body can never corrupt validation.
export function decodeBody(source: Readable, contentEncoding: string | string[] | undefined): Readable {
  const values = Array.isArray(contentEncoding) ? contentEncoding : [contentEncoding ?? ""];
  const tokens = values
    .flatMap((v) => v.split(","))
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t !== "");
  const known = new Set(["identity", "gzip", "x-gzip", "deflate", "br"]);
  if (tokens.some((t) => !known.has(t))) return source;
  let current: Readable = source;
  for (const token of [...tokens].reverse()) {
    if (token === "identity") continue;
    const decoder =
      token === "br" ? createBrotliDecompress() : token === "deflate" ? createInflate() : createGunzip();
    current.pipe(decoder);
    current = decoder;
  }
  if (current !== source) current.on("close", () => source.destroy());
  return current;
}

function headersFromRaw(raw: string[]): Headers {
  const headers = new Headers();
  for (let i = 0; i + 1 < raw.length; i += 2) {
    try {
      headers.append(raw[i]!, raw[i + 1]!);
    } catch {
      // Skip malformed pairs; one bad header must not fail the fetch.
    }
  }
  return headers;
}

// Converts a node:http response into the fetch-style Response the rest of
// the pipeline consumes. Multiple set-cookie pairs survive the conversion.
export function buildPinnedResponse(
  status: number,
  rawHeaders: string[],
  body: Readable | null
): Response {
  if (!Number.isInteger(status) || status < 200 || status > 599) {
    throw new Error(`invalid response status ${status}`);
  }
  const headers = headersFromRaw(rawHeaders);
  if (body === null) return new Response(null, { status, headers });
  // Readable.toWeb produces a genuine web stream; the cast bridges the
  // duplicate DOM/node typings for it, with no runtime effect.
  return new Response(Readable.toWeb(body) as unknown as ReadableStream<Uint8Array>, {
    status,
    headers,
  });
}

function attemptPinnedRequest(
  target: URL,
  address: string,
  init: PinnedFetchInit
): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    const isHttps = target.protocol === "https:";
    const host = stripBrackets(target.hostname);
    const options: HttpsRequestOptions = {
      protocol: target.protocol,
      host,
      port: target.port === "" ? (isHttps ? 443 : 80) : Number(target.port),
      path: `${target.pathname}${target.search}`,
      method: "GET",
      headers: { "accept-encoding": "gzip, deflate, br", ...init.headers },
      // Fresh connection every time: pooled sockets would skip the pinned
      // lookup and could cross per-hop validation boundaries.
      agent: false,
      lookup: createPinnedLookup([address]),
      signal: init.signal,
    };
    if (isHttps) {
      // Authenticate the hostname, not the pinned IP.
      options.servername = host;
    }
    let settled = false;
    const cleanup = (): void => {
      init.signal?.removeEventListener("abort", onAbort);
    };
    const onAbort = (): void => {
      msg?.destroy();
      req.destroy();
    };
    let req: ClientRequest;
    try {
      req = (isHttps ? httpsRequest : httpRequest)(options);
    } catch (err) {
      reject(err);
      return;
    }
    let msg: IncomingMessage | null = null;
    init.signal?.addEventListener("abort", onAbort, { once: true });
    req.on("error", (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    });
    req.on("close", cleanup);
    req.on("response", (incoming) => {
      msg = incoming;
      incoming.on("close", cleanup);
      const status = incoming.statusCode ?? 0;
      if (status < 200 || status > 299) {
        if (settled) return;
        settled = true;
        incoming.destroy();
        cleanup();
        try {
          resolve(buildPinnedResponse(status, incoming.rawHeaders, null));
        } catch (err) {
          reject(err);
        }
        return;
      }
      let stream: Readable;
      try {
        stream = decodeBody(incoming, incoming.headers["content-encoding"]);
      } catch (err) {
        if (settled) return;
        settled = true;
        incoming.destroy();
        cleanup();
        reject(err);
        return;
      }
      stream.on("error", (err) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err);
      });
      if (settled) return;
      settled = true;
      try {
        resolve(buildPinnedResponse(status, incoming.rawHeaders, stream));
      } catch (err) {
        stream.destroy();
        cleanup();
        reject(err);
      }
    });
    req.end();
  });
}

// Fetches one validated URL by connecting only to the given validated
// addresses (tried in order on connection-level failures). The URL itself
// MUST already have passed `validatePublicUrl`, and every address MUST
// already have passed SSRF validation.
export async function pinnedFetch(
  target: URL,
  addresses: string[],
  init: PinnedFetchInit = {}
): Promise<Response> {
  const valid = addresses.filter((a) => isIP(a) === 4 || isIP(a) === 6);
  if (valid.length === 0) {
    throw new Error("no validated address to connect to");
  }
  const signal = init.signal;
  if (signal?.aborted) throw abortError(signal);
  let lastError: unknown = null;
  for (const address of valid) {
    try {
      return await attemptPinnedRequest(target, address, init);
    } catch (err) {
      if (signal?.aborted) throw abortError(signal);
      if (!isRetryableConnectionError(err)) {
        throw wrapError("pinned request failed", err);
      }
      lastError = err;
    }
  }
  throw wrapError("all validated addresses failed", lastError);
}
