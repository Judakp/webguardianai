import test from "node:test";
import assert from "node:assert/strict";
import type { LookupOptions } from "node:dns";
import { Readable } from "node:stream";
import { gzipSync } from "node:zlib";
import { OnlineError } from "./errors.js";
import { fetchSite } from "./fetchSite.js";
import {
  buildPinnedResponse,
  createPinnedLookup,
  decodeBody,
  isRetryableConnectionError,
  stripBrackets,
} from "./pinnedFetch.js";
import { resolveValidatedAddresses, type HostResolver } from "./ssrf.js";

// Regression tests for validated-IP connection pinning and the body-read
// idle timeout. None of these touch the network: pinning is verified at
// the lookup-construction level (the connector never calls DNS), and the
// read path is exercised through mocked fetch implementations.

function lookupOnce(
  lookup: ReturnType<typeof createPinnedLookup>,
  hostname: string
): Promise<{ err: Error | null; address: string; family: number }> {
  return new Promise((resolve) => {
    lookup(hostname, {} as LookupOptions, (err, address, family) => {
      const first = Array.isArray(address) ? (address[0]?.address ?? "") : address;
      resolve({ err, address: first, family: family ?? -1 });
    });
  });
}

test("pinned lookup ignores DNS and returns the validated IPv4 address", async () => {
  const out = await lookupOnce(createPinnedLookup(["93.184.216.34"]), "anything.example");
  assert.equal(out.err, null);
  assert.equal(out.address, "93.184.216.34");
  assert.equal(out.family, 4);
});

test("pinned lookup returns IPv6 addresses with family 6", async () => {
  const out = await lookupOnce(createPinnedLookup(["2606:4700:4700::1111"]), "v6.example");
  assert.equal(out.err, null);
  assert.equal(out.address, "2606:4700:4700::1111");
  assert.equal(out.family, 6);
});

test("pinned lookup supports Node's all-addresses callback mode", async () => {
  const lookup = createPinnedLookup(["93.184.216.34", "2606:4700:4700::1111"]);
  const addresses = await new Promise<Array<{ address: string; family: number }>>((resolve, reject) => {
    lookup("site.example", { all: true } as LookupOptions, (err, result) => {
      if (err) reject(err);
      else resolve(Array.isArray(result) ? result : [{ address: result, family: 0 }]);
    });
  });
  assert.deepEqual(addresses, [
    { address: "93.184.216.34", family: 4 },
    { address: "2606:4700:4700::1111", family: 6 },
  ]);
});

test("pinned lookup honors a requested address family", async () => {
  const lookup = createPinnedLookup(["93.184.216.34", "2606:4700:4700::1111"]);
  const result = await new Promise<{ address: string; family: number }>((resolve, reject) => {
    lookup("site.example", { family: 6 } as LookupOptions, (err, address, family) => {
      if (err) reject(err);
      else resolve({ address: Array.isArray(address) ? address[0]!.address : address, family: family ?? 0 });
    });
  });
  assert.deepEqual(result, { address: "2606:4700:4700::1111", family: 6 });
});

test("pinned lookup skips malformed entries and fails closed when empty", async () => {
  const skipped = await lookupOnce(
    createPinnedLookup(["not-an-ip", "93.184.216.34"]),
    "site.example"
  );
  assert.equal(skipped.err, null);
  assert.equal(skipped.address, "93.184.216.34");

  for (const list of [[], ["bogus"], ["[::1]"]] as const) {
    const out = await lookupOnce(createPinnedLookup([...list]), "site.example");
    assert.ok(out.err instanceof Error, `expected failure for ${JSON.stringify(list)}`);
    assert.equal((out.err as NodeJS.ErrnoException).code, "ENOTFOUND");
  }
});

test("retryable classification covers refused/reset/unreachable, not TLS", () => {
  for (const code of [
    "ECONNREFUSED",
    "ECONNRESET",
    "ETIMEDOUT",
    "EHOSTUNREACH",
    "ENETUNREACH",
    "EPIPE",
  ]) {
    assert.equal(isRetryableConnectionError({ code }), true, code);
  }
  for (const err of [
    { code: "CERT_HAS_EXPIRED" },
    { code: "DEPTH_ZERO_SELF_SIGNED_CERT" },
    { code: "ENOTFOUND" },
    { code: 42 },
    {},
    null,
    "ECONNREFUSED",
  ]) {
    assert.equal(isRetryableConnectionError(err), false, JSON.stringify(err));
  }
});

test("stripBrackets unwraps one IPv6 literal pair only", () => {
  assert.equal(stripBrackets("[::1]"), "::1");
  assert.equal(stripBrackets("[2606:4700:4700::1111]"), "2606:4700:4700::1111");
  assert.equal(stripBrackets("example.com"), "example.com");
  assert.equal(stripBrackets("["), "[");
  assert.equal(stripBrackets("[]"), "[]");
});

test("resolveValidatedAddresses returns usable addresses for pinning", async () => {
  const resolver: HostResolver = async (host) => {
    if (host === "site.example") return ["93.184.216.34", "2606:4700:4700::1111"];
    throw new Error(`unexpected host: ${host}`);
  };
  assert.deepEqual(await resolveValidatedAddresses("site.example", resolver), [
    "93.184.216.34",
    "2606:4700:4700::1111",
  ]);
  assert.deepEqual(await resolveValidatedAddresses("93.184.216.34", resolver), ["93.184.216.34"]);
  assert.deepEqual(await resolveValidatedAddresses("[2606:4700:4700::1111]", resolver), [
    "2606:4700:4700::1111",
  ]);
  await assert.rejects(resolveValidatedAddresses("127.0.0.1", resolver), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "blocked-host");
    return true;
  });
});

const HTML = `<!doctype html><html><head><title>Stub</title></head><body><h1>Hi</h1></body></html>`;

const resolver: HostResolver = async (host: string) => {
  if (host === "site.example") return ["93.184.216.34"];
  if (host === "redirect.example") return ["93.184.216.35"];
  throw new Error(`unexpected host: ${host}`);
};

function htmlResponse(body: string): Response {
  return new Response(body, { status: 200, headers: { "content-type": "text/html" } });
}

test("a stalled body is cut off by the idle timeout, not the overall budget", async () => {
  let cancelled = false;
  let pulls = 0;
  const dripping = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls += 1;
      if (pulls === 1) {
        controller.enqueue(new TextEncoder().encode("<html>"));
        return;
      }
      return new Promise<never>(() => {});
    },
    cancel() {
      cancelled = true;
    },
  });
  const fetchImpl = (async () =>
    new Response(dripping, { status: 200, headers: { "content-type": "text/html" } })) as unknown as typeof fetch;
  const started = Date.now();
  await assert.rejects(
    fetchSite("https://site.example/", { resolver, fetchImpl, idleTimeoutMs: 50 }),
    (err: unknown) => {
      assert.ok(err instanceof OnlineError);
      assert.equal(err.code, "fetch-timeout");
      assert.match(err.message, /stalled/);
      return true;
    }
  );
  assert.ok(Date.now() - started < 10_000, "idle timeout must fire long before the overall budget");
  assert.equal(cancelled, true, "stalled stream must be cancelled");
});

test("a healthy body is unaffected by the idle timeout", async () => {
  const fetchImpl = (async () => htmlResponse(HTML)) as unknown as typeof fetch;
  const fetched = await fetchSite("https://site.example/", {
    resolver,
    fetchImpl,
    idleTimeoutMs: 5000,
  });
  assert.equal(fetched.finalUrl, "https://site.example/");
  assert.ok(fetched.body.includes("<h1>Hi</h1>"));
});

test("every redirect hop re-resolves instead of trusting a cached verdict", async () => {
  const resolved: string[] = [];
  const counting: HostResolver = async (host) => {
    resolved.push(host);
    return resolver(host);
  };
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url === "http://redirect.example/") {
      return new Response(null, { status: 301, headers: { location: "https://site.example/" } });
    }
    return htmlResponse(HTML);
  }) as unknown as typeof fetch;
  const fetched = await fetchSite("http://redirect.example/", {
    resolver: counting,
    fetchImpl,
  });
  assert.equal(fetched.redirectHops, 1);
  assert.deepEqual(resolved, ["redirect.example", "site.example"]);
});

test("DNS that flaps to a private address between hops is blocked", async () => {
  let calls = 0;
  const flapping: HostResolver = async (host) => {
    calls += 1;
    if (host !== "flap.example") throw new Error(`unexpected host: ${host}`);
    return calls === 1 ? ["93.184.216.34"] : ["10.0.0.9"];
  };
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url === "https://flap.example/") {
      return new Response(null, { status: 302, headers: { location: "https://flap.example/other" } });
    }
    throw new Error(`must not fetch rebound target: ${url}`);
  }) as unknown as typeof fetch;
  await assert.rejects(fetchSite("https://flap.example/", { resolver: flapping, fetchImpl }), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "blocked-host");
    return true;
  });
});

test("production path fails closed before connecting when already aborted", async () => {
  // No fetchImpl: exercises the pinned-connector branch with a pre-aborted
  // signal, which must reject without opening any socket.
  await assert.rejects(
    fetchSite("https://site.example/", { resolver, signal: AbortSignal.abort() }),
    (err: unknown) => {
      assert.ok(err instanceof OnlineError);
      assert.equal(err.code, "fetch-timeout");
      return true;
    }
  );
});

test("production path blocks private hosts without connecting", async () => {
  await assert.rejects(fetchSite("http://127.0.0.1/", { resolver }), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "blocked-host");
    return true;
  });
});

test("pinned response conversion round-trips body, headers, and cookies", async () => {
  const res = buildPinnedResponse(
    200,
    ["content-type", "text/html", "set-cookie", "a=1; Path=/", "set-cookie", "b=2; Path=/"],
    Readable.from([Buffer.from("<h1>Hi</h1>")])
  );
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "text/html");
  assert.deepEqual(res.headers.getSetCookie(), ["a=1; Path=/", "b=2; Path=/"]);
  assert.equal(await res.text(), "<h1>Hi</h1>");

  const redirect = buildPinnedResponse(301, ["location", "https://site.example/"], null);
  assert.equal(redirect.status, 301);
  assert.equal(redirect.headers.get("location"), "https://site.example/");

  assert.throws(() => buildPinnedResponse(99, [], null), /invalid response status/);
});

test("gzip bodies are decoded before the pipeline reads them", async () => {
  const gzipped = gzipSync(Buffer.from(HTML));
  const decoded = decodeBody(Readable.from([gzipped]), "gzip");
  const chunks: Buffer[] = [];
  for await (const chunk of decoded) chunks.push(Buffer.from(chunk));
  assert.equal(Buffer.concat(chunks).toString("utf-8"), HTML);
});

test("unknown content codings pass through instead of failing", () => {
  const source = Readable.from([Buffer.from("raw")]);
  assert.equal(decodeBody(source, "x-mystery"), source);
  assert.equal(decodeBody(source, undefined), source);
});
