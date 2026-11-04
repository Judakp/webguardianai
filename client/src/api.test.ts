import test from "node:test";
import assert from "node:assert/strict";
import { AnalyzeError, analyzeSite, getHealth, type Report } from "./api.js";

// Frontend API-layer tests (client/src/api.ts). They run under node:test with
// a stubbed global fetch — no browser, no server, no network, no new deps.
//
// Run: tsc client/src/api.ts client/src/api.test.ts --outDir tmp/wg-client-test \
//        --module nodenext --moduleResolution nodenext --target es2022 \
//        --strict --skipLibCheck && node --test tmp/wg-client-test/api.test.js

const realFetch: typeof fetch = globalThis.fetch;

function useFetch(stub: typeof fetch): void {
  globalThis.fetch = stub;
}

function restoreFetch(): void {
  globalThis.fetch = realFetch;
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function sampleReport(): Report {
  return {
    version: 1,
    id: "r-1",
    mode: "online",
    createdAt: new Date().toISOString(),
    summary: { total: 1, bySeverity: { info: 1, low: 0, medium: 0, high: 0, critical: 0 } },
    findings: [{ id: "engine-deterministic", title: "Deterministic checks only", severity: "info" }],
    analyzedUrl: "https://site.example/",
    finalUrl: "https://site.example/",
    engine: { kind: "deterministic", aiAvailable: false, aiBlocker: "MODEL_API_KEY is not configured" },
  };
}

// Hangs until aborted, then rejects like a real aborted fetch.
const abortAwareHang = (<T>(...args: unknown[]): Promise<T> => {
  const init = args[1] as { signal?: AbortSignal } | undefined;
  const signal = init?.signal;
  return new Promise<T>((_resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("aborted", "AbortError"));
      return;
    }
    signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
  });
}) as unknown as typeof fetch;

test("successful analysis returns the report", async () => {
  const report = sampleReport();
  const seen: string[] = [];
  useFetch((async (input: string | URL | Request) => {
    seen.push(String(input));
    return jsonResponse({ ok: true, report });
  }) as unknown as typeof fetch);
  try {
    const result = await analyzeSite("https://site.example/");
    assert.deepEqual(result, report);
    assert.deepEqual(seen, ["/api/online/analyze"]);
  } finally {
    restoreFetch();
  }
});

test("invalid-url responses keep code and status for the error UI", async () => {
  useFetch((async () =>
    jsonResponse({ ok: false, error: "only http:// and https:// URLs are supported", code: "invalid-url" }, 400)) as unknown as typeof fetch);
  try {
    await assert.rejects(analyzeSite("ftp://site.example/x"), (err: unknown) => {
      assert.ok(err instanceof AnalyzeError);
      assert.equal(err.code, "invalid-url");
      assert.equal(err.status, 400);
      assert.match(err.message, /http/);
      return true;
    });
  } finally {
    restoreFetch();
  }
});

test("blocked-host and busy codes pass through untouched", async () => {
  for (const [code, status] of [
    ["blocked-host", 400],
    ["busy", 429],
    ["dns-failed", 502],
    ["too-large", 413],
  ] as const) {
    useFetch((async () => jsonResponse({ ok: false, error: code, code }, status)) as unknown as typeof fetch);
    try {
      await assert.rejects(analyzeSite("https://site.example/"), (err: unknown) => {
        assert.ok(err instanceof AnalyzeError);
        assert.equal(err.code, code);
        assert.equal(err.status, status);
        return true;
      }, code);
    } finally {
      restoreFetch();
    }
  }
});

test("unreachable backend maps to network-error (backend unavailable UI)", async () => {
  useFetch((async () => {
    throw new TypeError("fetch failed");
  }) as unknown as typeof fetch);
  try {
    await assert.rejects(analyzeSite("https://site.example/"), (err: unknown) => {
      assert.ok(err instanceof AnalyzeError);
      assert.equal(err.code, "network-error");
      assert.equal(err.status, 0);
      assert.match(err.message, /Cannot reach the analysis server/);
      return true;
    });
  } finally {
    restoreFetch();
  }
});

test("non-JSON responses raise a status-carrying AnalyzeError", async () => {
  useFetch((async () => new Response("<html>proxy error</html>", { status: 502 })) as unknown as typeof fetch);
  try {
    await assert.rejects(analyzeSite("https://site.example/"), (err: unknown) => {
      assert.ok(err instanceof AnalyzeError);
      assert.equal(err.status, 502);
      return true;
    });
  } finally {
    restoreFetch();
  }
});

test("client-side timeout maps to fetch-timeout", async () => {
  useFetch(abortAwareHang);
  try {
    await assert.rejects(analyzeSite("https://site.example/", { timeoutMs: 50 }), (err: unknown) => {
      assert.ok(err instanceof AnalyzeError);
      assert.equal(err.code, "fetch-timeout");
      assert.equal(err.status, 504);
      return true;
    });
  } finally {
    restoreFetch();
  }
});

test("external cancel maps to cancelled", async () => {
  useFetch(abortAwareHang);
  const external = new AbortController();
  try {
    const pending = analyzeSite("https://site.example/", { signal: external.signal, timeoutMs: 5000 });
    external.abort(new DOMException("cancelled by user", "AbortError"));
    await assert.rejects(pending, (err: unknown) => {
      assert.ok(err instanceof AnalyzeError);
      assert.equal(err.code, "cancelled");
      assert.equal(err.status, 499);
      return true;
    });
  } finally {
    restoreFetch();
  }
});

test("getHealth returns status and throws when unhealthy", async () => {
  useFetch((async () => jsonResponse({ status: "ok" })) as unknown as typeof fetch);
  try {
    assert.deepEqual(await getHealth(), { status: "ok" });
  } finally {
    restoreFetch();
  }
  useFetch((async () => new Response("down", { status: 500 })) as unknown as typeof fetch);
  try {
    await assert.rejects(getHealth(), /health check failed: 500/);
  } finally {
    restoreFetch();
  }
});
