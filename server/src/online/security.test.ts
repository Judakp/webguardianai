import test from "node:test";
import assert from "node:assert/strict";
import { OnlineError } from "./errors.js";
import { analyzeOnlineSite } from "./pipeline.js";
import type { HostResolver } from "./ssrf.js";

// Pipeline/fetch-level security tests. Every external website response is
// mocked (stub resolver + stub fetch); no test here touches the network.

const resolver: HostResolver = async (host: string) => {
  if (host === "site.example") return ["93.184.216.34"];
  if (host === "v6.example") return ["2606:4700:4700::1111"];
  throw new Error(`unexpected host: ${host}`);
};

function stubFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) =>
    handler(String(input), init)) as unknown as typeof fetch;
}

function htmlResponse(body: string): Response {
  return new Response(body, { status: 200, headers: { "content-type": "text/html" } });
}

const HTML = `<!doctype html><html><head><title>T</title></head><body><h1>Hi</h1></body></html>`;

async function expectCode(promise: Promise<unknown>, code: string, url: string): Promise<void> {
  await assert.rejects(promise, (err: unknown) => {
    assert.ok(err instanceof OnlineError, `expected OnlineError for ${url}`);
    assert.equal(err.code, code, `wrong code for ${url}: ${err.code}`);
    return true;
  }, url);
}

test("IPv6 loopback/private literals are blocked before fetch", async () => {
  const fetchImpl = stubFetch(() => {
    throw new Error("must not fetch");
  });
  for (const url of [
    "http://[::1]/",
    "http://[::1]:3000/admin",
    "http://[::]/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[ff02::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:10.0.0.1]/",
    "http://[::ffff:169.254.169.254]/",
  ]) {
    await expectCode(analyzeOnlineSite(url, { resolver, fetchImpl }), "blocked-host", url);
  }
});

test("obfuscated loopback and private IPv4 forms are blocked", async () => {
  const fetchImpl = stubFetch(() => {
    throw new Error("must not fetch");
  });
  for (const url of [
    "http://2130706433/", // decimal 127.0.0.1
    "http://0x7f.0x0.0x0.0x1/", // hex 127.0.0.1
    "http://0177.0.0.01/", // octal-ish 127.0.0.1
    "http://10.0.0.1/",
    "http://172.16.5.4:8080/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:7f00:1]/",
  ]) {
    await expectCode(analyzeOnlineSite(url, { resolver, fetchImpl }), "blocked-host", url);
  }
});

test("unsupported protocols are rejected as invalid urls", async () => {
  const fetchImpl = stubFetch(() => {
    throw new Error("must not fetch");
  });
  for (const url of [
    "ftp://site.example/file",
    "file:///etc/passwd",
    "data:text/html,<h1>x</h1>",
    "javascript:alert(1)",
    "gopher://site.example/",
    "https://user:pass@site.example/",
  ]) {
    await expectCode(analyzeOnlineSite(url, { resolver, fetchImpl }), "invalid-url", url);
  }
});

test("DNS failure surfaces as dns-failed", async () => {
  const failingResolver: HostResolver = async () => {
    throw new Error("getaddrinfo ENOTFOUND");
  };
  const fetchImpl = stubFetch(() => {
    throw new Error("must not fetch");
  });
  await expectCode(
    analyzeOnlineSite("https://missing.example/", { resolver: failingResolver, fetchImpl }),
    "dns-failed",
    "missing.example"
  );
});

test("hosts resolving to private or loopback addresses are blocked", async () => {
  const byHost: Record<string, string[]> = {
    "site.example": ["93.184.216.34"],
    "rebind.example": ["10.9.9.9"],
    "v6rebind.example": ["::1"],
    "mixed.example": ["93.184.216.34", "192.168.0.5"],
  };
  const mixedResolver: HostResolver = async (host: string) => {
    if (!(host in byHost)) throw new Error(`unexpected host: ${host}`);
    return byHost[host]!;
  };
  const fetchImpl = stubFetch(() => htmlResponse(HTML));
  for (const host of ["rebind.example", "v6rebind.example", "mixed.example"]) {
    await expectCode(
      analyzeOnlineSite(`https://${host}/`, { resolver: mixedResolver, fetchImpl }),
      "blocked-host",
      host
    );
  }
  // Control: the public host still analyzes fine with the same stubs.
  const report = await analyzeOnlineSite("https://site.example/", {
    resolver: mixedResolver,
    fetchImpl,
  });
  assert.equal(report.mode, "online");
});

test("redirect to an unsupported protocol is rejected", async () => {
  const fetchImpl = stubFetch((url) => {
    if (url === "https://site.example/") {
      return new Response(null, { status: 302, headers: { location: "file:///etc/passwd" } });
    }
    throw new Error(`must not fetch ${url}`);
  });
  await expectCode(
    analyzeOnlineSite("https://site.example/", { resolver, fetchImpl }),
    "invalid-url",
    "redirect-to-file"
  );
});

test("redirect without a target surfaces as fetch-failed", async () => {
  const fetchImpl = stubFetch(() => new Response(null, { status: 301 }));
  await expectCode(
    analyzeOnlineSite("https://site.example/", { resolver, fetchImpl }),
    "fetch-failed",
    "redirect-without-location"
  );
});

test("fetch network errors surface as fetch-failed", async () => {
  const fetchImpl = stubFetch(() => {
    throw new TypeError("fetch failed");
  });
  await expectCode(
    analyzeOnlineSite("https://site.example/", { resolver, fetchImpl }),
    "fetch-failed",
    "network-error"
  );
});

test("aborted analysis surfaces as fetch-timeout (fast path)", async () => {
  const controller = new AbortController();
  controller.abort(new Error("overall budget exceeded"));
  const fetchImpl = stubFetch(() => {
    throw new DOMException("aborted", "AbortError");
  });
  const { fetchSite } = await import("./fetchSite.js");
  await assert.rejects(
    fetchSite("https://site.example/", { resolver, fetchImpl, signal: controller.signal }),
    (err: unknown) => {
      assert.ok(err instanceof OnlineError);
      assert.equal(err.code, "fetch-timeout");
      return true;
    }
  );
});

test("unresponsive server triggers the per-hop fetch timeout", async () => {
  // Mock fetch hangs until the hop timeout aborts it (~10s), then rejects
  // like a real aborted fetch would.
  const fetchImpl = stubFetch((_url, init) => {
    return new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal as AbortSignal | undefined;
      if (signal?.aborted) {
        reject(new DOMException("aborted", "AbortError"));
        return;
      }
      signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), {
        once: true,
      });
    });
  });
  const { fetchSite } = await import("./fetchSite.js");
  await assert.rejects(fetchSite("https://site.example/", { resolver, fetchImpl, fetchTimeoutMs: 50 }), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "fetch-timeout");
    return true;
  });
});

test("unresponsive DNS triggers the DNS timeout", async () => {
  // Resolver never settles; the guard must fail closed (~10s), not hang.
  const hangingResolver: HostResolver = () => new Promise<string[]>(() => {});
  const { resolveAndValidateHost } = await import("./ssrf.js");
  await assert.rejects(resolveAndValidateHost("slow.example", hangingResolver, 50), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "dns-failed");
    return true;
  });
});

test("public IPv6 pages analyze end to end", async () => {
  const fetchImpl = stubFetch(() => htmlResponse(HTML));
  const report = await analyzeOnlineSite("https://v6.example/", { resolver, fetchImpl });
  assert.equal(report.mode, "online");
  assert.equal(report.analyzedUrl, "https://v6.example/");
  assert.ok(report.findings.some((f) => f.id === "engine-deterministic"));
});
