import { useEffect, useMemo, useRef, useState } from "react";
import { AnalyzeError, analyzeSite, getHealth, type Finding, type Report, type Severity } from "./api";
import "./styles.css";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const EXAMPLE_URLS = ["https://example.com/", "https://example.org/", "https://www.iana.org/"];

const STAGES = ["Validating URL", "Fetching page", "Running checks", "Preparing report"];

interface ErrorState {
  message: string;
  detail?: string;
  code?: string;
  status?: number;
}

function validateUrl(raw: string): { value?: string; error?: string } {
  const trimmed = raw.trim();
  if (trimmed === "") return { error: "Enter a website URL, for example https://example.com/." };
  if (trimmed.length > 2048) return { error: "That URL is too long (maximum 2048 characters)." };
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { error: "That URL looks invalid. Use a full address starting with http:// or https://." };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { error: "Only http:// and https:// URLs can be analyzed." };
  }
  if (parsed.username !== "" || parsed.password !== "") {
    return { error: "URLs with credentials (user:pass@host) are not accepted." };
  }
  if (parsed.hostname === "") return { error: "That URL has no hostname." };
  return { value: trimmed };
}

function friendlyError(err: unknown): ErrorState {
  if (err instanceof AnalyzeError) {
    const code = err.code;
    if (err.status === 0 || code === "network-error") {
      return {
        message: "Cannot reach the analysis server.",
        detail: "Start it with `npm run dev:server`, then try again.",
        code,
        status: err.status,
      };
    }
    switch (code) {
      case "cancelled":
        return { message: "Analysis cancelled.", code, status: err.status };
      case "fetch-timeout":
        return { message: err.message, detail: "Slow sites can take up to ~2 minutes.", code, status: err.status };
      case "invalid-url":
        return {
          message: "That URL was rejected. Use a full public address like https://example.com/.",
          detail: err.message,
          code,
          status: err.status,
        };
      case "blocked-host":
        return {
          message: "That host cannot be analyzed: only public websites are allowed (no localhost or private IPs).",
          detail: err.message,
          code,
          status: err.status,
        };
      case "busy":
        return { message: "The server is busy. Wait a moment, then retry.", detail: err.message, code, status: err.status };
      case "too-large":
        return { message: "That page is too large to analyze (over the 2 MB limit).", detail: err.message, code, status: err.status };
      case "not-html":
        return { message: "That URL did not return an HTML page.", detail: err.message, code, status: err.status };
      case "too-many-redirects":
        return { message: "That site redirected too many times (over 5 hops).", detail: err.message, code, status: err.status };
      case "dns-failed":
        return { message: "That hostname could not be resolved (DNS failed).", detail: err.message, code, status: err.status };
      case "fetch-failed":
        return { message: "That page could not be fetched.", detail: err.message, code, status: err.status };
      default:
        return { message: err.message || "Analysis failed.", code, status: err.status };
    }
  }
  return { message: err instanceof Error ? err.message : "Analysis failed." };
}

function buildSummary(report: Report): string {
  const by = report.summary.bySeverity;
  const actionable = report.findings.filter((f) => f.id !== "engine-deterministic" && f.id !== "engine-muse-spark");
  const critical = by.critical ?? 0;
  const high = by.high ?? 0;
  const medium = by.medium ?? 0;
  if (actionable.length === 0) return "No issues were found. The page passed every deterministic check.";
  if (critical + high === 0 && medium === 0) {
    return `Found ${actionable.length} low-risk observation${actionable.length === 1 ? "" : "s"}. No critical, high, or medium issues were detected.`;
  }
  const parts: string[] = [];
  if (critical > 0) parts.push(`${critical} critical`);
  if (high > 0) parts.push(`${high} high`);
  if (medium > 0) parts.push(`${medium} medium`);
  return `Found ${actionable.length} issue${actionable.length === 1 ? "" : "s"} (${parts.join(", ")}). Start with the important issues below.`;
}

function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

export default function App() {
  const [health, setHealth] = useState<"checking" | "ok" | "down">("checking");
  const [url, setUrl] = useState<string>("https://example.com/");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [busy, setBusy] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [elapsed, setElapsed] = useState<number>(0);
  const [error, setError] = useState<ErrorState | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const abortRef = useRef<AbortController | null>(null);
  const timersRef = useRef<number[]>([]);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    getHealth()
      .then(() => setHealth("ok"))
      .catch(() => setHealth("down"));
  }, []);

  useEffect(() => {
    return () => {
      for (const id of timersRef.current) window.clearInterval(id);
      abortRef.current?.abort();
    };
  }, []);

  const byCategory = useMemo(() => {
    const counts = new Map<string, number>();
    if (!report) return counts;
    for (const finding of report.findings) {
      const key = finding.category?.trim() === "" ? "General" : (finding.category ?? "General");
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return new Map([...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])));
  }, [report]);

  const grouped = useMemo(() => {
    const map = new Map<Severity, Finding[]>();
    if (!report) return map;
    for (const severity of SEVERITY_ORDER) {
      map.set(
        severity,
        report.findings.filter((f) => f.severity === severity)
      );
    }
    return map;
  }, [report]);

  const important = useMemo(() => {
    if (!report) return [];
    return report.findings
      .filter((f) => f.id !== "engine-deterministic" && (f.severity === "critical" || f.severity === "high"))
      .slice(0, 5);
  }, [report]);

  const stageIndex = progress < 25 ? 0 : progress < 55 ? 1 : progress < 85 ? 2 : 3;

  function clearTimers(): void {
    for (const id of timersRef.current) window.clearInterval(id);
    timersRef.current = [];
  }

  async function onAnalyze(event?: { preventDefault: () => void }): Promise<void> {
    event?.preventDefault();
    if (busy) return;
    const validation = validateUrl(url);
    if (validation.error || !validation.value) {
      setFieldError(validation.error ?? "Invalid URL.");
      inputRef.current?.focus();
      return;
    }
    const target = validation.value;
    setFieldError(null);
    setError(null);
    setReport(null);
    setBusy(true);
    setProgress(4);
    setElapsed(0);

    const controller = new AbortController();
    abortRef.current = controller;
    const started = Date.now();
    const elapsedTimer = window.setInterval(() => {
      setElapsed(Math.floor((Date.now() - started) / 1000));
    }, 500);
    const progressTimer = window.setInterval(() => {
      setProgress((prev) => {
        if (prev >= 92) return prev;
        const increment = prev < 30 ? 2.5 : prev < 60 ? 1.4 : 0.6;
        return Math.min(92, prev + increment);
      });
    }, 500);
    timersRef.current = [elapsedTimer, progressTimer];

    try {
      const result = await analyzeSite(target, { signal: controller.signal });
      setProgress(100);
      setReport(result);
      const open = new Set<string>();
      for (const finding of result.findings) {
        if (finding.severity === "critical" || finding.severity === "high") open.add(finding.id);
      }
      setExpanded(open);
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      clearTimers();
      abortRef.current = null;
      setBusy(false);
    }
  }

  function onCancel(): void {
    abortRef.current?.abort(new DOMException("cancelled by user", "AbortError"));
  }

  function toggleFinding(id: string): void {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function expandAll(): void {
    if (!report) return;
    setExpanded(new Set(report.findings.map((f) => f.id)));
  }

  function collapseAll(): void {
    setExpanded(new Set());
  }

  function useExample(example: string): void {
    setUrl(example);
    setFieldError(null);
    setError(null);
    inputRef.current?.focus();
  }

  function startNew(): void {
    setReport(null);
    setError(null);
    setFieldError(null);
    setProgress(0);
    setElapsed(0);
    inputRef.current?.focus();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  const displayedUrl = report?.analyzedUrl ?? report?.finalUrl ?? "";
  const finalUrl = report?.finalUrl ?? "";
  const redirected = displayedUrl !== "" && finalUrl !== "" && displayedUrl !== finalUrl;

  return (
    <div className="wg-page">
      <header className="wg-header">
        <div className="wg-brand">
          <span className="wg-logo" aria-hidden="true">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M12 2.5 20 6v6c0 5-3.4 8.6-8 9.5C7.4 20.6 4 17 4 12V6l8-3.5Z"
                stroke="#fff"
                strokeWidth="1.8"
                strokeLinejoin="round"
              />
              <path d="m8.8 12 2.2 2.2 4.2-4.4" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <div>
            <h1>WebGuardian AI</h1>
            <p className="wg-tagline">Website security, SEO &amp; quality analysis</p>
          </div>
        </div>
        <span
          className="wg-status-pill"
          role="status"
          aria-live="polite"
          aria-label={health === "ok" ? "Backend online" : health === "checking" ? "Checking backend" : "Backend unreachable"}
        >
          <span className={`wg-dot${health === "ok" ? " ok" : health === "down" ? " bad" : ""}`} aria-hidden="true" />
          {health === "ok" ? "Backend online" : health === "checking" ? "Checking backend…" : "Backend unreachable"}
        </span>
      </header>

      <main>
        <section className="wg-card" aria-labelledby="analyze-heading">
          <h2 id="analyze-heading">Analyze a website</h2>
          <p className="wg-lead">
            Enter any public URL. WebGuardian fetches the page and runs static checks across security headers,
            SEO, performance, accessibility, and best practices; then explains every finding with evidence and
            a recommended fix.
          </p>
          <ul className="wg-feature-list">
            <li>
              <strong>Security headers</strong>
              Transport, CSP, framing, cookies &amp; mixed content
            </li>
            <li>
              <strong>SEO &amp; structure</strong>
              Titles, meta, headings, canonical &amp; links
            </li>
            <li>
              <strong>Quality signals</strong>
              Accessibility, forms, scripts &amp; images
            </li>
          </ul>
          <p className="wg-engine-note">
            The HTML engine and Playwright collect technical evidence. Muse Spark adds reasoning.
          </p>

          <form
            onSubmit={(e) => {
              void onAnalyze(e);
            }}
            noValidate
          >
            <div className="wg-form-row">
              <div className="wg-field">
                <label className="wg-label" htmlFor="site-url">
                  Website URL
                </label>
                <input
                  ref={inputRef}
                  id="site-url"
                  className="wg-input"
                  type="url"
                  required
                  placeholder="https://example.com/"
                  value={url}
                  disabled={busy}
                  aria-invalid={fieldError ? "true" : undefined}
                  aria-describedby={fieldError ? "url-error" : "url-hint"}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    if (fieldError) setFieldError(null);
                  }}
                />
                {fieldError ? (
                  <p className="wg-field-error" id="url-error" role="alert">
                    {fieldError}
                  </p>
                ) : (
                  <p className="wg-hint" id="url-hint">
                    Full public address starting with http:// or https://. Private hosts and localhost are blocked.
                  </p>
                )}
              </div>
              <button type="submit" className="wg-btn wg-btn-primary" disabled={busy}>
                {busy ? "Analyzing…" : "Analyze Website"}
              </button>
            </div>
          </form>

          <div className="wg-examples">
            <span>Try an example:</span>
            {EXAMPLE_URLS.map((example) => (
              <button
                key={example}
                type="button"
                className="wg-example-btn"
                disabled={busy}
                onClick={() => useExample(example)}
              >
                {example}
              </button>
            ))}
          </div>

          {busy && (
            <div className="wg-progress" role="status" aria-live="polite" aria-label="Analysis in progress">
              <div className="wg-progress-top">
                <span>
                  {STAGES[stageIndex]}… ({elapsed}s elapsed)
                </span>
                <button type="button" className="wg-link-btn" onClick={onCancel}>
                  Cancel
                </button>
              </div>
              <div className="wg-progress-bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress)}>
                <div className="wg-progress-fill" style={{ width: `${Math.round(progress)}%` }} />
              </div>
              <ol className="wg-progress-steps">
                {STAGES.map((stage, index) => (
                  <li key={stage} data-active={index === stageIndex} data-done={index < stageIndex}>
                    {index < stageIndex ? "✓ " : ""}
                    {stage}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {error && !busy && (
            <div className="wg-alert" role="alert">
              <strong>Analysis failed: {error.message}</strong>
              {error.detail && <div>{error.detail}</div>}
              {(error.code || error.status !== undefined) && (
                <div>
                  <code>
                    {error.code ? `code: ${error.code}` : ""}
                    {error.code && error.status !== undefined ? " · " : ""}
                    {error.status !== undefined ? `status: ${error.status}` : ""}
                  </code>
                </div>
              )}
              {error.code !== "cancelled" && (
                <div className="wg-alert-actions">
                  <button
                    type="button"
                    className="wg-btn wg-btn-secondary"
                    onClick={() => {
                      void onAnalyze();
                    }}
                  >
                    Retry analysis
                  </button>
                </div>
              )}
            </div>
          )}
        </section>

        {!report && !busy && !error && (
          <section className="wg-card" aria-label="No report yet">
            <div className="wg-empty">
              <strong>No report yet</strong>
              Enter a URL above and choose “Analyze Website” to get your first report.
            </div>
          </section>
        )}

        {report && !busy && (
          <section className="wg-card" aria-labelledby="report-heading" aria-live="polite">
            <div className="wg-section-head">
              <h2 id="report-heading">Report</h2>
              <button type="button" className="wg-btn wg-btn-secondary" style={{ marginTop: 0 }} onClick={startNew}>
                New analysis
              </button>
            </div>
            <p className="wg-report-meta">
              {displayedUrl !== "" && (
                <span>
                  URL:{" "}
                  <a href={displayedUrl} target="_blank" rel="noreferrer">
                    {displayedUrl}
                  </a>
                </span>
              )}
              {redirected && (
                <span>
                  Final URL:{" "}
                  <a href={finalUrl} target="_blank" rel="noreferrer">
                    {finalUrl}
                  </a>
                </span>
              )}
              <span>Date: {formatDate(report.createdAt)}</span>
              <span>Report ID: {report.id}</span>
              {report.engine && <span>Engines: {report.engine.browserAvailable ? "HTML + Playwright" : "HTML only"} · {report.engine.aiAvailable ? "Muse Spark connected" : "Muse Spark not connected"}</span>}
              {report.engine?.browserBlocker && <span>Browser note: {report.engine.browserBlocker}</span>}
            </p>

            <div className="wg-summary-box">
              <div className="wg-total-line">
                <span className="wg-total-number">{report.summary.total}</span>
                <span>
                  finding{report.summary.total === 1 ? "" : "s"} · {buildSummary(report)}
                </span>
              </div>
            </div>

            <div className="wg-count-grid">
              <div className="wg-count-card">
                <h3>By severity</h3>
                <ul className="wg-pills">
                  {SEVERITY_ORDER.map((severity) => (
                    <li key={severity} className={`wg-pill ${severity}`}>
                      {SEVERITY_LABEL[severity]}: {report.summary.bySeverity[severity] ?? 0}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="wg-count-card">
                <h3>By category</h3>
                {byCategory.size === 0 ? (
                  <p className="wg-lead" style={{ margin: 0 }}>
                    No findings.
                  </p>
                ) : (
                  <ul className="wg-pills">
                    {[...byCategory.entries()].map(([category, count]) => (
                      <li key={category} className="wg-pill category">
                        {category}: {count}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            {important.length > 0 && (
              <>
                <div className="wg-section-head">
                  <h3>Important issues ({important.length})</h3>
                </div>
                <ul className="wg-important-list">
                  {important.map((finding) => (
                    <li key={finding.id} className={finding.severity}>
                      <strong>
                        [{SEVERITY_LABEL[finding.severity]}] {finding.title}
                      </strong>
                      {finding.category && <span> · {finding.category}</span>}
                      {finding.recommendation && <div>Fix: {finding.recommendation}</div>}
                    </li>
                  ))}
                </ul>
              </>
            )}

            <div className="wg-section-head">
              <h3>All findings ({report.findings.length})</h3>
              <div>
                <button type="button" className="wg-link-btn" onClick={expandAll}>
                  Expand all
                </button>
                {" · "}
                <button type="button" className="wg-link-btn" onClick={collapseAll}>
                  Collapse all
                </button>
              </div>
            </div>

            {SEVERITY_ORDER.map((severity) => {
              const items = grouped.get(severity) ?? [];
              if (items.length === 0) return null;
              return (
                <div key={severity}>
                  <h4 className="wg-group-title">
                    {SEVERITY_LABEL[severity]} ({items.length})
                  </h4>
                  {items.map((finding) => {
                    const isOpen = expanded.has(finding.id);
                    return (
                      <article key={finding.id} className="wg-finding">
                        <button
                          type="button"
                          className="wg-finding-head wg-toggle"
                          aria-expanded={isOpen}
                          aria-controls={`finding-${finding.id}`}
                          onClick={() => toggleFinding(finding.id)}
                        >
                          <span className={`wg-badge ${severity}`}>{SEVERITY_LABEL[severity]}</span>
                          <span className="wg-finding-title">{finding.title}</span>
                          {finding.category && <span className="wg-cat">{finding.category}</span>}
                          <span className="wg-chevron" aria-hidden="true">
                            {isOpen ? "▾" : "▸"}
                          </span>
                        </button>
                        {isOpen && (
                          <div className="wg-finding-body" id={`finding-${finding.id}`}>
                            {finding.description && <p>{finding.description}</p>}
                            {finding.whyItMatters && (
                              <p>
                                <strong>Why it matters: </strong>
                                {finding.whyItMatters}
                              </p>
                            )}
                            {finding.evidence && (
                              <>
                                <p style={{ marginBottom: "0.3rem" }}>
                                  <strong>Evidence</strong>
                                </p>
                                <pre className="wg-evidence">{finding.evidence}</pre>
                              </>
                            )}
                            {finding.recommendation && (
                              <p>
                                <strong>Recommendation: </strong>
                                {finding.recommendation}
                              </p>
                            )}
                            {finding.confidence && (
                              <p className="wg-confidence">Confidence: {finding.confidence}</p>
                            )}
                          </div>
                        )}
                      </article>
                    );
                  })}
                </div>
              );
            })}
          </section>
        )}
      </main>

      <footer className="wg-footer">
        WebGuardian AI · Deterministic static analysis of public pages · Slow sites may take up to ~2 minutes
      </footer>
    </div>
  );
}
