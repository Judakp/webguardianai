import test from "node:test";
import assert from "node:assert/strict";
import express, { type Express } from "express";
import type { AddressInfo } from "node:net";
import { createEmptyReport } from "webguardian-shared";
import { healthHandler } from "../app.js";
import { createOnlineRouter, getActiveOnlineAnalyses } from "./router.js";
import type { HostResolver } from "./ssrf.js";

// HTTP-level API tests. The app under test runs on an ephemeral localhost
// port (test harness only), and every external website response is mocked via
// injected resolver/fetch — no real site is ever contacted.

const HTML = `<!doctype html><html lang="en"><head>
<title>Example Services</title>
<meta name="description" content="A mocked example page.">
</head><body><h1>Welcome</h1><a href="/about">About</a></body></html>`;

const resolver: HostResolver = async (host: string) => {
  if (host === "site.example") return ["93.184.216.34"];
  if (host === "localhost") return ["127.0.0.1"];
  throw new Error(`unexpected host: ${host}`);
};

function mockFetch(body: string = HTML): typeof fetch {
  return (async () =>
    new Response(body, { status: 200, headers: { "content-type": "text/html" } })) as unknown as typeof fetch;
}

interface TestServer {
  base: string;
  close: () => Promise<void>;
}

async function startServer(routerDeps: { resolver: HostResolver; fetchImpl: typeof fetch }): Promise<TestServer> {
  const app: Express = express();
  app.use(express.json({ limit: "1mb", strict: false }));
  app.get("/api/health", healthHandler);
  app.use("/api/online", createOnlineRouter(routerDeps));
  const server = await new Promise<import("node:http").Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
  };
}

interface AnalyzeBody {
  ok: boolean;
  report?: {
    version: number;
    id: string;
    mode: string;
    createdAt: string;
    summary: { total: number; bySeverity: Record<string, number> };
    findings: Array<{ id: string; title: string; severity: string; evidence?: string }>;
    analyzedUrl?: string;
    finalUrl?: string;
    engine?: { kind: string; aiAvailable: boolean; aiBlocker?: string };
  };
  error?: string;
  code?: string;
}

async function postAnalyze(base: string, payload: unknown): Promise<{ status: number; body: AnalyzeBody }> {
  const res = await fetch(`${base}/api/online/analyze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  return { status: res.status, body: (await res.json()) as AnalyzeBody };
}

test("POST /api/online/analyze succeeds with a mocked site", async () => {
  const srv = await startServer({ resolver, fetchImpl: mockFetch() });
  try {
    const { status, body } = await postAnalyze(srv.base, { url: "https://site.example/" });
    assert.equal(status, 200);
    assert.equal(body.ok, true);
    assert.ok(body.report, "missing report");
    assert.equal(body.report.mode, "online");
    assert.equal(body.report.version, 1);
    assert.ok(body.report.id.length > 0);
    assert.ok(!Number.isNaN(Date.parse(body.report.createdAt)));
    // Contract the frontend renders: all five severities, findings, engine, urls.
    assert.deepEqual(Object.keys(body.report.summary.bySeverity).sort(), [
      "critical",
      "high",
      "info",
      "low",
      "medium",
    ]);
    assert.equal(body.report.summary.total, body.report.findings.length);
    assert.ok(
      body.report.findings.every((f) => f.id && f.title && f.severity),
      "every finding needs id/title/severity"
    );
    assert.ok(body.report.findings.some((f) => f.id === "engine-deterministic"));
    assert.equal(body.report.engine?.kind, "deterministic");
    assert.equal(body.report.engine?.aiAvailable, false);
    assert.equal(body.report.engine?.kind, "deterministic");
    assert.match(body.report.engine?.aiBlocker ?? "", /MODEL_API_KEY|Muse Spark/);
    assert.equal(body.report.analyzedUrl, "https://site.example/");
    assert.equal(typeof body.report.finalUrl, "string");
  } finally {
    await srv.close();
  }
});

test("invalid urls are rejected with the code the frontend maps", async () => {
  const srv = await startServer({ resolver, fetchImpl: mockFetch() });
  try {
    for (const url of ["not-a-url", "ftp://site.example/x", "https://user:pw@site.example/"]) {
      const { status, body } = await postAnalyze(srv.base, { url });
      assert.equal(status, 400, url);
      assert.equal(body.ok, false);
      assert.equal(body.code, "invalid-url", url);
      assert.equal(typeof body.error, "string");
    }
  } finally {
    await srv.close();
  }
});

test("blocked hosts are rejected without fetching", async () => {
  let fetches = 0;
  const countingFetch = (async () => {
    fetches += 1;
    return new Response("x", { status: 200, headers: { "content-type": "text/html" } });
  }) as unknown as typeof fetch;
  const srv = await startServer({ resolver, fetchImpl: countingFetch });
  try {
    for (const url of ["http://127.0.0.1/", "http://localhost:3000/", "http://[::1]/", "http://169.254.169.254/"]) {
      const { status, body } = await postAnalyze(srv.base, { url });
      assert.equal(status, 400, url);
      assert.equal(body.code, "blocked-host", url);
    }
    assert.equal(fetches, 0);
  } finally {
    await srv.close();
  }
});

test("missing or non-string url fields are rejected", async () => {
  const srv = await startServer({ resolver, fetchImpl: mockFetch() });
  try {
    for (const payload of [{}, { url: "" }, { url: "   " }, { url: 42 }, { url: null }, null]) {
      const { status, body } = await postAnalyze(srv.base, payload);
      assert.equal(status, 400, JSON.stringify(payload));
      assert.equal(body.ok, false);
      assert.equal(body.code, "invalid-url");
    }
  } finally {
    await srv.close();
  }
});

test("dns failures keep the error code the frontend renders", async () => {
  const failingResolver: HostResolver = async () => {
    throw new Error("getaddrinfo ENOTFOUND");
  };
  const srv = await startServer({ resolver: failingResolver, fetchImpl: mockFetch() });
  try {
    const { status, body } = await postAnalyze(srv.base, { url: "https://missing.example/" });
    assert.equal(status, 502);
    assert.equal(body.code, "dns-failed");
    assert.equal(typeof body.error, "string");
  } finally {
    await srv.close();
  }
});

test("concurrent overload returns busy (429) and recovers", async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const gatedFetch = (async () => {
    await gate;
    return new Response(HTML, { status: 200, headers: { "content-type": "text/html" } });
  }) as unknown as typeof fetch;
  const srv = await startServer({ resolver, fetchImpl: gatedFetch });
  try {
    assert.equal(getActiveOnlineAnalyses(), 0);
    const inFlight = Array.from({ length: 4 }, () => postAnalyze(srv.base, { url: "https://site.example/" }));
    // Wait until all four slots are occupied before sending the fifth.
    const deadline = Date.now() + 5000;
    while (getActiveOnlineAnalyses() < 4) {
      if (Date.now() > deadline) throw new Error("slots never filled");
      await new Promise((r) => setTimeout(r, 10));
    }
    const busy = await postAnalyze(srv.base, { url: "https://site.example/" });
    assert.equal(busy.status, 429);
    assert.equal(busy.body.code, "busy");
    release();
    const results = await Promise.all(inFlight);
    assert.ok(results.every((r) => r.status === 200 && r.body.ok), "gated requests should succeed after release");
    assert.equal(getActiveOnlineAnalyses(), 0);
  } finally {
    await srv.close();
  }
});

test("GET /api/health keeps the shape the frontend status pill needs", async () => {
  const srv = await startServer({ resolver, fetchImpl: mockFetch() });
  try {
    const res = await fetch(`${srv.base}/api/health`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: "ok" });
  } finally {
    await srv.close();
  }
});

test("empty report contract stays renderable (frontend empty state)", () => {
  const report = createEmptyReport("online", "empty-1");
  assert.equal(report.summary.total, 0);
  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.summary.bySeverity, { info: 0, low: 0, medium: 0, high: 0, critical: 0 });
});
