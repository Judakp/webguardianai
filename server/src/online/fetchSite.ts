import { OnlineError } from "./errors.js";
import {
  ONLINE_BODY_IDLE_TIMEOUT_MS,
  ONLINE_FETCH_TIMEOUT_MS,
  ONLINE_MAX_BODY_BYTES,
  ONLINE_MAX_REDIRECTS,
  ONLINE_USER_AGENT,
} from "./limits.js";
import { pinnedFetch } from "./pinnedFetch.js";
import {
  resolveValidatedAddresses,
  validatePublicUrl,
  validateRedirectTarget,
  type HostResolver,
} from "./ssrf.js";

export interface FetchedSite {
  startUrl: string;
  finalUrl: string;
  status: number;
  contentType: string | null;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  bodyBytes: number;
  redirectHops: number;
}

export interface FetchSiteOptions {
  resolver?: HostResolver;
  fetchImpl?: typeof fetch;
  signal?: AbortSignal;
  // Overrides ONLINE_BODY_IDLE_TIMEOUT_MS. Tests use a short value to
  // exercise the slow-drip path without waiting; production omits it.
  idleTimeoutMs?: number;
  fetchTimeoutMs?: number;
  dnsTimeoutMs?: number;
}

const WANTED_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "server",
  "x-powered-by",
] as const;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function shortCause(err: unknown): string {
  const code =
    typeof err === "object" && err !== null && "cause" in err
      ? (err as { cause?: { code?: unknown } }).cause?.code
      : undefined;
  return typeof code === "string" && code.length > 0 ? ` (${code.slice(0, 24)})` : "";
}

// Reads one body chunk, giving up if no data arrives within the idle
// budget. Each successful read restarts the budget for the next chunk.
async function readWithIdleTimeout(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  idleTimeoutMs: number
): Promise<ReadableStreamReadResult<Uint8Array>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      reader.read(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new OnlineError(
                "fetch-timeout",
                `fetching the page stalled (no data for ${idleTimeoutMs / 1000}s)`
              )
            ),
          idleTimeoutMs
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// Secure single-page fetch. Follows redirects manually so every hop is
// revalidated (scheme, credentials, DNS) immediately before connecting,
// and the production connector pins each connection to the validated
// addresses so DNS rebinding cannot swap the destination after validation.
// Response bodies are streamed with a hard byte cap plus an idle timeout;
// page scripts are never executed — the body is returned as inert text
// for the parser.
export async function fetchSite(startUrl: string, opts: FetchSiteOptions = {}): Promise<FetchedSite> {
  const resolver = opts.resolver;
  const fetchImpl = opts.fetchImpl;
  const idleTimeoutMs = opts.idleTimeoutMs ?? ONLINE_BODY_IDLE_TIMEOUT_MS;
  const fetchTimeoutMs = opts.fetchTimeoutMs ?? ONLINE_FETCH_TIMEOUT_MS;
  const dnsTimeoutMs = opts.dnsTimeoutMs ?? undefined;
  let current = validatePublicUrl(startUrl);
  const startHref = current.href;
  let redirectHops = 0;

  for (;;) {
    const addresses = await resolveValidatedAddresses(current.hostname, resolver, dnsTimeoutMs);

    const hopController = new AbortController();
    const hopTimer = setTimeout(() => hopController.abort(new Error("hop timeout")), fetchTimeoutMs);
    const signal = opts.signal ? AbortSignal.any([opts.signal, hopController.signal]) : hopController.signal;
    const requestHeaders = {
      "user-agent": ONLINE_USER_AGENT,
      accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    };

    let res: Response;
    try {
      // Injected fetch implementations (tests) bypass pinning by design;
      // production always goes through the pinned connector below.
      res =
        fetchImpl !== undefined
          ? await fetchImpl(current.href, { method: "GET", redirect: "manual", signal, headers: requestHeaders })
          : await pinnedFetch(current, addresses, { signal, headers: requestHeaders });
    } catch (err) {
      clearTimeout(hopTimer);
      if (signal.aborted) {
        throw new OnlineError("fetch-timeout", `fetching the page timed out after ${fetchTimeoutMs / 1000}s`);
      }
      throw new OnlineError("fetch-failed", `could not fetch the page${shortCause(err)}`);
    }

    clearTimeout(hopTimer);

    if (REDIRECT_STATUSES.has(res.status)) {
      await res.body?.cancel().catch(() => {});
      if (redirectHops >= ONLINE_MAX_REDIRECTS) {
        throw new OnlineError(
          "too-many-redirects",
          `page redirects more than ${ONLINE_MAX_REDIRECTS} times`
        );
      }
      const location = res.headers.get("location");
      if (!location) {
        throw new OnlineError("fetch-failed", `server returned redirect ${res.status} without a target`);
      }
      current = validateRedirectTarget(current, location);
      redirectHops += 1;
      continue;
    }

    if (res.status < 200 || res.status > 299) {
      await res.body?.cancel().catch(() => {});
      throw new OnlineError("fetch-failed", `site returned HTTP ${res.status}`);
    }

    const rawContentType = res.headers.get("content-type");
    const contentType = rawContentType?.split(";")[0]?.trim().toLowerCase() ?? null;
    if (contentType !== "text/html" && contentType !== "application/xhtml+xml") {
      await res.body?.cancel().catch(() => {});
      throw new OnlineError(
        "not-html",
        contentType ? `page is ${contentType}, not HTML` : "page has no HTML content type"
      );
    }

    const chunks: Uint8Array[] = [];
    let bodyBytes = 0;
    try {
      if (!res.body) throw new OnlineError("fetch-failed", "empty response from site");
      const reader = res.body.getReader();
      try {
        for (;;) {
          const { done, value } = await readWithIdleTimeout(reader, idleTimeoutMs);
          if (done) break;
          bodyBytes += value.byteLength;
          if (bodyBytes > ONLINE_MAX_BODY_BYTES) {
            throw new OnlineError(
              "too-large",
              `page exceeds the ${Math.round(ONLINE_MAX_BODY_BYTES / 1024 / 1024)} MiB inspection limit`
            );
          }
          chunks.push(value);
        }
      } catch (err) {
        await reader.cancel().catch(() => {});
        throw err;
      }
    } catch (err) {
      if (err instanceof OnlineError) throw err;
      if (signal.aborted) {
        throw new OnlineError("fetch-timeout", "fetching the page timed out while reading");
      }
      throw new OnlineError("fetch-failed", `interrupted while reading the page${shortCause(err)}`);
    }
    const joined = new Uint8Array(bodyBytes);
    let offset = 0;
    for (const chunk of chunks) {
      joined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const body = new TextDecoder("utf-8", { fatal: false }).decode(joined);

    const headers: Record<string, string> = {};
    for (const name of WANTED_HEADERS) {
      const value = res.headers.get(name);
      if (value !== null) headers[name] = value.slice(0, 2000);
    }
    const setCookies = res.headers
      .getSetCookie?.()
      .slice(0, 20)
      .map((c) => c.slice(0, 2000)) ?? [];

    return {
      startUrl: startHref,
      finalUrl: current.href,
      status: res.status,
      contentType,
      headers,
      setCookies,
      body,
      bodyBytes,
      redirectHops,
    };
  }
}
