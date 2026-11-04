import { chromium, type Browser, type BrowserContext, type Route } from "playwright";
import { pinnedFetch } from "./pinnedFetch.js";
import {
  BROWSER_MAX_REDIRECTS,
  BROWSER_MAX_REQUESTS,
  BROWSER_MAX_RESOURCE_BYTES,
  BROWSER_MAX_TOTAL_BYTES,
  BROWSER_NAVIGATION_TIMEOUT_MS,
  BROWSER_TOTAL_TIMEOUT_MS,
} from "./limits.js";
import {
  resolveValidatedAddresses,
  validatePublicUrl,
  validateRedirectTarget,
  type HostResolver,
} from "./ssrf.js";
import type { Finding } from "webguardian-shared";

export interface BrowserInspection {
  available: boolean;
  findings: Finding[];
  finalUrl?: string;
  title?: string;
  requestCount: number;
  failedRequests: string[];
  consoleErrors: string[];
  reason?: string;
}

interface BrowserOptions {
  resolver?: HostResolver;
  enabled?: boolean;
  navigationTimeoutMs?: number;
  totalTimeoutMs?: number;
}

const SAFE_RESPONSE_HEADERS = new Set([
  "content-type", "content-language", "cache-control", "last-modified", "etag",
  "content-security-policy", "content-security-policy-report-only", "x-frame-options",
  "x-content-type-options", "referrer-policy", "permissions-policy",
  "access-control-allow-origin", "access-control-allow-credentials",
  "access-control-allow-methods", "access-control-allow-headers",
  "access-control-expose-headers", "access-control-max-age", "vary",
]);

function makeFinding(
  id: string, title: string, severity: Finding["severity"], description: string,
  evidence: string, recommendation: string,
): Finding {
  return {
    id, title, severity, category: "Technical", confidence: "high", description,
    evidence: evidence.slice(0, 500), recommendation,
  };
}

async function readBounded(response: Response, maxBytes: number): Promise<Uint8Array> {
  const length = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(length) && length > maxBytes) throw new Error("resource too large");
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error("resource too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

/**
 * Browser HTTP(S) requests are never sent directly by Chromium. Chromium's
 * resolver is disabled and every request is intercepted, DNS-validated,
 * fetched through the existing pinned-IP connector, and size-limited.
 */
async function fulfillPinned(
  route: Route,
  resolver: HostResolver | undefined,
  budget: { requests: number; bytes: number },
  signal: AbortSignal,
): Promise<void> {
  const request = route.request();
  const method = request.method().toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    await route.fulfill({ status: 405, body: "Method blocked by WebGuardian browser inspection" });
    return;
  }
  let current: URL;
  try { current = validatePublicUrl(request.url()); }
  catch {
    await route.fulfill({ status: 403, body: "Blocked by WebGuardian URL policy" });
    return;
  }
  budget.requests += 1;
  if (budget.requests > BROWSER_MAX_REQUESTS) {
    await route.fulfill({ status: 429, body: "Browser request budget exceeded" });
    return;
  }

  for (let hop = 0; hop <= BROWSER_MAX_REDIRECTS; hop += 1) {
    if (signal.aborted) {
      await route.fulfill({ status: 504, body: "Browser inspection timed out" }).catch(() => {});
      return;
    }
    let response: Response;
    const requestController = new AbortController();
    const requestTimer = setTimeout(() => requestController.abort(new Error("browser resource timeout")), 8_000);
    const requestSignal = AbortSignal.any([signal, requestController.signal]);
    try {
      const addresses = await resolveValidatedAddresses(current.hostname, resolver);
      response = await pinnedFetch(current, addresses, {
        signal: requestSignal,
        headers: {
          "user-agent": "WebGuardianAI/1.0 (safe browser inspection)",
          accept: request.headers()["accept"] ?? "*/*",
          "accept-language": request.headers()["accept-language"] ?? "en",
        },
      });
    } catch {
      await route.fulfill({ status: signal.aborted ? 504 : 502, body: "Resource blocked or unavailable" }).catch(() => {});
      return;
    } finally {
      clearTimeout(requestTimer);
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel().catch(() => {});
      if (!location || hop === BROWSER_MAX_REDIRECTS) {
        await route.fulfill({ status: 502, body: "Redirect limit exceeded" });
        return;
      }
      try { current = validateRedirectTarget(current, location); }
      catch {
        await route.fulfill({ status: 403, body: "Redirect blocked by WebGuardian URL policy" });
        return;
      }
      continue;
    }
    const maxBytes = request.isNavigationRequest() ? 2 * 1024 * 1024 : BROWSER_MAX_RESOURCE_BYTES;
    let body: Uint8Array;
    try { body = method === "HEAD" ? new Uint8Array() : await readBounded(response, maxBytes); }
    catch {
      await route.fulfill({ status: 413, body: "Resource size limit exceeded" });
      return;
    }
    budget.bytes += body.byteLength;
    if (budget.bytes > BROWSER_MAX_TOTAL_BYTES) {
      await route.fulfill({ status: 413, body: "Browser total data budget exceeded" });
      return;
    }
    const headers: Record<string, string> = {};
    for (const [name, value] of response.headers.entries()) {
      if (SAFE_RESPONSE_HEADERS.has(name.toLowerCase())) headers[name] = value;
    }
    await route.fulfill({ status: response.status, headers, body: Buffer.from(body) });
    return;
  }
}

export async function analyzeWithPlaywright(
  rawUrl: string,
  options: BrowserOptions = {},
): Promise<BrowserInspection> {
  if (options.enabled === false || process.env.PLAYWRIGHT_ENABLED === "false") {
    return {
      available: false, findings: [], requestCount: 0, failedRequests: [], consoleErrors: [],
      reason: "Browser inspection is disabled. Set PLAYWRIGHT_ENABLED=true to enable it.",
    };
  }
  let browser: Browser | undefined;
  let context: BrowserContext | undefined;
  const findings: Finding[] = [];
  const failedRequests: string[] = [];
  const consoleErrors: string[] = [];
  const budget = { requests: 0, bytes: 0 };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.totalTimeoutMs ?? BROWSER_TOTAL_TIMEOUT_MS);
  try {
    const start = validatePublicUrl(rawUrl);
    browser = await chromium.launch({
      headless: true,
      chromiumSandbox: true,
      timeout: 15_000,
      args: [
        "--host-resolver-rules=MAP * ~NOTFOUND",
        "--disable-quic", "--disable-background-networking", "--disable-sync",
        "--no-first-run", "--no-default-browser-check",
      ],
    });
    context = await browser.newContext({
      viewport: { width: 1366, height: 768 },
      javaScriptEnabled: true,
      acceptDownloads: false,
      serviceWorkers: "block",
      permissions: [],
    });
    await context.route("**/*", async (route) => {
      const requestUrl = route.request().url();
      // In-page data/blob URLs do not open external network connections.
      if (/^(data|blob|about):/i.test(requestUrl)) { await route.continue(); return; }
      await fulfillPinned(route, options.resolver, budget, controller.signal);
    });
    // WebSocket connections are a separate transport and must not bypass
    // the HTTP(S) request interceptor.
    await context.routeWebSocket("**/*", (socket) => socket.close());
    const page = await context.newPage();
    page.on("pageerror", (error) => {
      if (consoleErrors.length < 10) consoleErrors.push(error.message.slice(0, 240));
    });
    page.on("console", (message) => {
      if (message.type() === "error" && consoleErrors.length < 10) consoleErrors.push(message.text().slice(0, 240));
    });
    page.on("requestfailed", (request) => {
      if (failedRequests.length < 12) {
        let host = "unknown";
        try { host = new URL(request.url()).hostname; } catch { /* keep unknown */ }
        failedRequests.push(`${request.resourceType()}: ${host} (${request.failure()?.errorText ?? "failed"})`);
      }
    });
    const navigation = await page.goto(start.href, {
      waitUntil: "domcontentloaded",
      timeout: options.navigationTimeoutMs ?? BROWSER_NAVIGATION_TIMEOUT_MS,
    });
    if (!navigation) throw new Error("browser did not receive a navigation response");
    await page.waitForTimeout(500).catch(() => {});
    const info = await page.evaluate(() => ({
      title: document.title || "",
      finalUrl: location.href,
      viewportWidth: window.innerWidth,
      documentWidth: Math.max(document.documentElement?.scrollWidth ?? 0, document.body?.scrollWidth ?? 0),
      bodyPresent: Boolean(document.body),
    }));
    if (!info.bodyPresent) findings.push(makeFinding(
      "browser-empty-document", "The browser rendered an empty document", "high",
      "The page loaded but no document body was available after client-side rendering.",
      "document.body was absent", "Check the application entry point, hydration process, and runtime errors.",
    ));
    if (info.documentWidth > info.viewportWidth + 8) findings.push(makeFinding(
      "browser-horizontal-overflow", "Horizontal overflow detected at desktop viewport", "medium",
      "The rendered document is wider than the browser viewport.",
      `Document width ${info.documentWidth}px; viewport ${info.viewportWidth}px`,
      "Inspect fixed-width elements, oversized media, and CSS overflow rules.",
    ));
    if (consoleErrors.length) findings.push(makeFinding(
      "browser-console-errors", "JavaScript errors observed in the browser", "high",
      "The browser reported JavaScript exceptions or console errors during page loading.",
      consoleErrors.slice(0, 5).join(" | "),
      "Inspect the browser console and fix the first underlying exception before addressing follow-on errors.",
    ));
    if (failedRequests.length) findings.push(makeFinding(
      "browser-failed-requests", "Some page resources failed to load", "medium",
      "The browser could not load one or more requested resources. Some failures may reflect WebGuardian's safety and resource limits.",
      failedRequests.slice(0, 6).join(" | "),
      "Verify resource URLs, server responses, CORS configuration, and whether each resource is required.",
    ));
    if (controller.signal.aborted) {
      throw new Error("browser inspection total time limit exceeded");
    }
    return {
      available: true, findings, finalUrl: info.finalUrl, title: info.title,
      requestCount: budget.requests, failedRequests, consoleErrors,
    };
  } catch (error) {
    return {
      available: false, findings: [], requestCount: budget.requests, failedRequests, consoleErrors,
      reason: controller.signal.aborted
        ? "Browser inspection exceeded its total time limit."
        : error instanceof Error ? error.message.slice(0, 300) : "Browser inspection failed.",
    };
  } finally {
    clearTimeout(timer);
    await context?.close().catch(() => {});
    await browser?.close().catch(() => {});
  }
}
