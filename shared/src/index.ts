export const REPORT_VERSION = 1;

export type AnalysisMode = "online" | "offline";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

// "info" is the informational level. Finding categories for the online engine.
export type FindingCategory =
  | "SEO"
  | "Security"
  | "Performance"
  | "Accessibility"
  | "Technical"
  | "Best practices";

export type FindingConfidence = "high" | "medium" | "low";

export type LanguageId =
  | "html"
  | "css"
  | "javascript"
  | "typescript"
  | "jsx"
  | "tsx"
  | "php"
  | "python"
  | "unknown";

export type FrameworkId = "react" | "nextjs" | "laravel" | "unknown";

export type RuntimeId = "nodejs" | "unknown";

export type DetectionConfidence = "detected" | "likely" | "unknown";

export interface StackEvidence {
  path: string;
  marker: string;
}

export interface StackDetection {
  framework: FrameworkId;
  frameworkConfidence: DetectionConfidence;
  runtime: RuntimeId;
  runtimeConfidence: DetectionConfidence;
  evidence: StackEvidence[];
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category?: FindingCategory;
  description?: string;
  whyItMatters?: string;
  confidence?: FindingConfidence;
  file?: string;
  line?: number;
  evidence?: string;
  recommendation?: string;
}

export interface ReportSummary {
  total: number;
  bySeverity: Record<Severity, number>;
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
  mode: AnalysisMode;
  createdAt: string;
  summary: ReportSummary;
  findings: Finding[];
  languages?: LanguageId[];
  stack?: StackDetection;
  analyzedUrl?: string;
  finalUrl?: string;
  engine?: EngineInfo;
}

export function createEmptyReport(mode: AnalysisMode, id: string): Report {
  return {
    version: REPORT_VERSION,
    id,
    mode,
    createdAt: new Date().toISOString(),
    summary: { total: 0, bySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 } },
    findings: [],
  };
}

export function summarizeFindings(findings: Finding[]): ReportSummary {
  const bySeverity: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }
  return { total: findings.length, bySeverity };
}
