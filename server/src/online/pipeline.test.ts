import test from "node:test";
import assert from "node:assert/strict";
import { OnlineError } from "./errors.js";
import { analyzeOnlineSite } from "./pipeline.js";
import type { HostResolver } from "./ssrf.js";

const HTML = `<!doctype html><html><head><title>Stub</title>
<meta name="description" content="stub page"></head>
<body><h1>Hi</h1><a href="/a">a</a></body></html>`;

const resolver: HostResolver = async (host: string) => {
  if (host === "site.example") return ["93.184.216.34"];
  if (host === "redirect.example") return ["93.184.216.35"];
  if (host === "localhost") return ["127.0.0.1"];
  throw new Error(`unexpected host: ${host}`);
};

function stubFetch(handler: (url: string) => Response): typeof fetch {
  return (async (input: string | URL | Request) => handler(String(input))) as unknown as typeof fetch;
}

function htmlResponse(body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", ...headers },
  });
}

test("happy path returns a versioned online report with summary", async () => {
  const fetchImpl = stubFetch((url) => {
    assert.equal(url, "https://site.example/");
    return htmlResponse(HTML, {
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
    });
  });
  const report = await analyzeOnlineSite("https://site.example/", { resolver, fetchImpl });
  assert.equal(report.mode, "online");
  assert.equal(report.version, 1);
  assert.ok(report.id.length > 0);
  assert.ok(!Number.isNaN(Date.parse(report.createdAt)));
  assert.deepEqual(report.languages, ["html"]);
  assert.equal(report.summary.total, report.findings.length);
  const byId = new Map(report.findings.map((f) => [f.id, f]));
  assert.equal(byId.get("transport-https")?.severity, "info");
  assert.equal(byId.get("hsts-enabled")?.severity, "info");
  assert.ok(report.findings.every((f) => typeof f.evidence === "string" && typeof f.recommendation === "string"));
});

test("redirects are followed hop by hop and revalidated", async () => {
  const seen: string[] = [];
  const fetchImpl = stubFetch((url) => {
    seen.push(url);
    if (url === "http://redirect.example/") {
      return new Response(null, { status: 301, headers: { location: "https://site.example/" } });
    }
    return htmlResponse(HTML);
  });
  const report = await analyzeOnlineSite("http://redirect.example/", { resolver, fetchImpl });
  assert.deepEqual(seen, ["http://redirect.example/", "https://site.example/"]);
  assert.ok(report.findings.some((f) => f.id === "transport-upgrades-to-https"));
});

test("redirect to a private address is blocked", async () => {
  const fetchImpl = stubFetch((url) => {
    if (url === "https://site.example/") {
      return new Response(null, { status: 302, headers: { location: "http://127.0.0.1:8000/" } });
    }
    throw new Error(`must not fetch ${url}`);
  });
  await assert.rejects(analyzeOnlineSite("https://site.example/", { resolver, fetchImpl }), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "blocked-host");
    assert.equal(err.status, 400);
    return true;
  });
});

test("redirect to a host resolving privately is blocked", async () => {
  const mixedResolver: HostResolver = async (host: string) => {
    if (host === "site.example") return ["93.184.216.34"];
    if (host === "rebind.example") return ["10.9.9.9"];
    throw new Error(`unexpected host: ${host}`);
  };
  const fetchImpl = stubFetch((url) => {
    if (url === "https://site.example/") {
      return new Response(null, { status: 302, headers: { location: "https://rebind.example/" } });
    }
    throw new Error(`must not fetch ${url}`);
  });
  await assert.rejects(
    analyzeOnlineSite("https://site.example/", { resolver: mixedResolver, fetchImpl }),
    (err: unknown) => {
      assert.ok(err instanceof OnlineError);
      assert.equal(err.code, "blocked-host");
      return true;
    }
  );
});

test("non-html pages are rejected without analysis", async () => {
  const fetchImpl = stubFetch(() => new Response("%PDF-1.4", { status: 200, headers: { "content-type": "application/pdf" } }));
  await assert.rejects(analyzeOnlineSite("https://site.example/", { resolver, fetchImpl }), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "not-html");
    assert.equal(err.status, 415);
    return true;
  });
});

test("error statuses are reported honestly", async () => {
  const fetchImpl = stubFetch(() => new Response("nope", { status: 404 }));
  await assert.rejects(analyzeOnlineSite("https://site.example/", { resolver, fetchImpl }), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "fetch-failed");
    assert.ok(err.message.includes("404"));
    return true;
  });
});

test("oversized pages are rejected", async () => {
  const big = "x".repeat(2 * 1024 * 1024 + 1);
  const fetchImpl = stubFetch(() => htmlResponse(`<html><body>${big}</body></html>`));
  await assert.rejects(analyzeOnlineSite("https://site.example/", { resolver, fetchImpl }), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "too-large");
    assert.equal(err.status, 413);
    return true;
  });
});

test("redirect loops are bounded", async () => {
  const fetchImpl = stubFetch(
    () => new Response(null, { status: 302, headers: { location: "https://site.example/loop" } })
  );
  await assert.rejects(analyzeOnlineSite("https://site.example/", { resolver, fetchImpl }), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "too-many-redirects");
    return true;
  });
});

test("invalid and blocked start urls never reach fetch", async () => {
  const fetchImpl = stubFetch(() => {
    throw new Error("must not fetch");
  });
  for (const [url, code] of [
    ["http://127.0.0.1/", "blocked-host"],
    ["http://localhost:3000/", "blocked-host"],
    ["http://169.254.169.254/latest/", "blocked-host"],
    ["file:///etc/passwd", "invalid-url"],
    ["not-a-url", "invalid-url"],
  ] as const) {
    await assert.rejects(analyzeOnlineSite(url, { resolver, fetchImpl }), (err: unknown) => {
      assert.ok(err instanceof OnlineError);
      assert.equal(err.code, code);
      return true;
    }, url);
  }
});
