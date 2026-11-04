
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

export async function getHealth(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE_URL}/api/health`);
  if (!res.ok) throw new Error(`health check failed: ${res.status}`);
  return (await res.json()) as { status: string };
}

// Local mirror of the shared report contract (the client has no dependency
// on webguardian-shared; these shapes must stay compatible with it).
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type FindingCategory =
  | "SEO"
  | "Security"
  | "Performance"
  | "Accessibility"
  | "Technical"
  | "Best practices";

export type FindingConfidence = "high" | "medium" | "low";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category?: FindingCategory | string;
  description?: string;
  whyItMatters?: string;
  confidence?: FindingConfidence;
  evidence?: string;
  recommendation?: string;
}

export interface EngineInfo {
  kind: "deterministic" | "browser" | "hybrid";
  aiAvailable: boolean;
  aiBlocker?: string;
  browserAvailable?: boolean;
  browserBlocker?: string;
}

export interface Report {
  version: number;
  id: string;
  mode: "online" | "offline";
  createdAt: string;
  summary: { total: number; bySeverity: Record<Severity, number> };
  findings: Finding[];
  analyzedUrl?: string;
  finalUrl?: string;
  engine?: EngineInfo;
}

export class AnalyzeError extends Error {
  readonly code?: string;
  readonly status: number;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "AnalyzeError";
    this.status = status;
    this.code = code;
  }
}

export interface AnalyzeOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

const DEFAULT_ANALYZE_TIMEOUT_MS = 130_000;

interface AnalyzeResponseBody {
  ok: boolean;
  report?: Report;
  error?: string;
  code?: string;
}

export async function analyzeSite(
  url: string,
  options: AnalyzeOptions = {}
): Promise<Report> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_ANALYZE_TIMEOUT_MS;
  const controller = new AbortController();
  let timedOut = false;

  const onExternalAbort = (): void => {
    controller.abort(options.signal?.reason);
  };

  if (options.signal) {
    if (options.signal.aborted) {
      controller.abort(options.signal.reason);
    } else {
      options.signal.addEventListener("abort", onExternalAbort, { once: true });
    }
  }

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new DOMException("analysis timed out", "TimeoutError"));
  }, timeoutMs);

  try {
    let res: Response;

    try {
      res = await fetch(`${API_BASE_URL}/api/online/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });
    } catch (err) {
      if (controller.signal.aborted) {
        if (timedOut) {
          throw new AnalyzeError(
            "Analysis timed out after ~2 minutes. The site may be slow — try again.",
            504,
            "fetch-timeout"
          );
        }

        if (options.signal?.aborted) {
          throw new AnalyzeError("Analysis cancelled.", 499, "cancelled");
        }

        throw new AnalyzeError("Analysis was aborted.", 499, "cancelled");
      }

      throw new AnalyzeError(
        err instanceof Error
          ? `Cannot reach the analysis server: ${err.message}`
          : "Cannot reach the analysis server.",
        0,
        "network-error"
      );
    }

    let body: AnalyzeResponseBody;

    try {
      body = (await res.json()) as AnalyzeResponseBody;
    } catch {
      throw new AnalyzeError(
        `Analysis failed: unexpected server response (${res.status}).`,
        res.status
      );
    }

    if (!res.ok || !body.ok || !body.report) {
      throw new AnalyzeError(
        body.error ?? `analysis failed: ${res.status}`,
        res.status,
        body.code
      );
    }

    return body.report;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", onExternalAbort);
  }
}
