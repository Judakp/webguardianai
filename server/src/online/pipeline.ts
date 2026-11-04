
import { randomUUID } from "node:crypto";
import {
  REPORT_VERSION,
  summarizeFindings,
  type Report,
} from "webguardian-shared";
import { dedupeFindings, runOnlineChecks } from "./checks.js";
import { OnlineError } from "./errors.js";
import { extractEvidence, type LinkCheck } from "./extract.js";
import { fetchSite } from "./fetchSite.js";
import { analyzeWithPlaywright } from "./browserAnalyzer.js";
import { ONLINE_OVERALL_TIMEOUT_MS } from "./limits.js";
import type { HostResolver } from "./ssrf.js";
import {
  AI_MODEL,
  aiEngineFinding,
  analyzeWithMuseSpark,
  deterministicEngineFinding,
  getAiStatus,
} from "./ai.js";

// Verifies a sample of extracted link destinations. Implementations MUST
// SSRF-validate every URL (scheme, credentials, DNS — see ssrf.ts) before
// connecting, bound concurrency and timeouts, and never forward credentials.
// No default implementation: without an injected verifier the pipeline makes
// no extra requests and honestly reports link checks as not evaluated.
export type LinkVerifier = (urls: string[]) => Promise<LinkCheck[]>;

export interface AnalyzeOnlineOptions {
  resolver?: HostResolver;
  fetchImpl?: typeof fetch;
  linkVerifier?: LinkVerifier;
  aiFetchImpl?: typeof fetch;
  aiApiKey?: string;
  aiBaseUrl?: string;
  aiModel?: string;
  browserEnabled?: boolean;
}

const MAX_VERIFIED_LINKS = 20;

// End-to-end online analysis: securely fetch one page, extract static
// evidence, run deterministic checks, and optionally inspect the rendered
// page in a network-guarded browser. Website content remains untrusted data;
// Muse Spark receives only structured evidence and findings, never page scripts.
export async function analyzeOnlineSite(
  rawUrl: string,
  opts: AnalyzeOnlineOptions = {}
): Promise<Report> {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    ONLINE_OVERALL_TIMEOUT_MS
  );

  if (typeof timer.unref === "function") {
    timer.unref();
  }

  try {
    const fetched = await fetchSite(rawUrl, {
      resolver: opts.resolver,
      fetchImpl: opts.fetchImpl,
      signal: controller.signal,
    });

    const evidence = extractEvidence(fetched);

    if (opts.linkVerifier && evidence.links.length > 0) {
      try {
        const sample = evidence.links
          .slice(0, MAX_VERIFIED_LINKS)
          .map((l) => l.href);

        const checked = await opts.linkVerifier(sample);

        if (Array.isArray(checked)) {
          evidence.linkChecks = checked
            .filter(
              (c) =>
                c &&
                typeof c.href === "string" &&
                typeof c.ok === "boolean"
            )
            .slice(0, MAX_VERIFIED_LINKS);
        }
      } catch {
        // A failed verifier must never fail the analysis; checks will report
        // link verification as not evaluated.
      }
    }

    const staticFindings = runOnlineChecks(evidence);

    // Tests that inject a fake fetch do not launch a real browser.
    // Production uses Playwright unless explicitly disabled.
    const browser = await analyzeWithPlaywright(fetched.finalUrl, {
      resolver: opts.resolver,
      enabled:
        opts.browserEnabled ??
        (opts.fetchImpl === undefined &&
          process.env.PLAYWRIGHT_ENABLED !== "false"),
    });

    const deterministicFindings = [
      ...staticFindings,
      ...browser.findings,
    ];

    const baseFindings = [
      deterministicEngineFinding(),
      ...deterministicFindings,
    ];

    // Muse Spark diagnostic logs.
    console.log("[WebGuardian][Muse Spark] Analyse IA démarrée");

    const ai = await analyzeWithMuseSpark(
      evidence,
      deterministicFindings,
      {
        fetchImpl: opts.aiFetchImpl,
        apiKey: opts.aiApiKey,
        baseUrl: opts.aiBaseUrl,
        model: opts.aiModel,
      }
    );

    console.log("[WebGuardian][Muse Spark] Résultat :", {
      available: ai.available,
      model: ai.model ?? opts.aiModel ?? AI_MODEL,
      findingsCount: ai.findings.length,
      reason: ai.reason ?? null,
    });

    const findings = dedupeFindings([
      ...baseFindings,
      ...(ai.available
        ? [
            aiEngineFinding(ai.model ?? opts.aiModel ?? AI_MODEL),
            ...ai.findings,
          ]
        : []),
    ]);

    const aiStatus = getAiStatus();
    const aiAvailable = ai.available;

    return {
      version: REPORT_VERSION,
      id: randomUUID(),
      mode: "online",
      createdAt: new Date().toISOString(),
      summary: summarizeFindings(findings),
      findings,
      languages: ["html"],
      analyzedUrl: fetched.startUrl,
      finalUrl: fetched.finalUrl,
      engine: {
        kind: aiAvailable
          ? "hybrid"
          : browser.available
            ? "browser"
            : "deterministic",
        aiAvailable,
        aiBlocker: aiAvailable
          ? undefined
          : ai.reason ?? aiStatus.reason,
        browserAvailable: browser.available,
        browserBlocker: browser.available
          ? undefined
          : browser.reason,
      },
    };
  } catch (err) {
    if (
      controller.signal.aborted &&
      !(err instanceof OnlineError)
    ) {
      throw new OnlineError(
        "fetch-timeout",
        "analysis exceeded the overall time budget"
      );
    }

    throw err;
  } finally {
    clearTimeout(timer);
  }
}
