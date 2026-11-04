import type { LanguageId } from "webguardian-shared";
import { BINARY_PROBE_BYTES, MAX_PATH_CHARS } from "./limits.js";

const EXTENSION_LANGUAGE: Record<string, LanguageId> = {
  ".html": "html",
  ".htm": "html",
  ".css": "css",
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".jsx": "jsx",
  ".tsx": "tsx",
  ".php": "php",
  ".py": "python",
};

const MANIFEST_BASENAMES = new Set(["package.json", "composer.json"]);

// Generated/dependency directories excluded from analysis. Matched against
// exact directory segments only (never the file basename, never substrings),
// so `coverage.js` or `my-dist/app.js` are still analyzed.
const EXCLUDED_DIR_SEGMENTS = new Set([
  "node_modules",
  "vendor",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage",
]);

// ZIP Slip guard. Returns the normalized `a/b/c` form or null when the entry
// must never be trusted (absolute, drive-letter, empty/dot/dotdot segment,
// over-long). Backslashes are normalized before inspection so `..\\` attacks
// fail the same way as `../`.
export function normalizeEntryName(raw: string): string | null {
  if (!raw || raw.length > MAX_PATH_CHARS) return null;
  const unified = raw.replace(/\\/g, "/");
  if (unified.startsWith("/") || /^[a-zA-Z]:/.test(unified)) return null;
  const segments = unified.split("/");
  for (const segment of segments) {
    if (segment === "" || segment === "." || segment === "..") return null;
  }
  return unified;
}

export function classifyBasename(basename: string): LanguageId | "manifest" | null {
  if (MANIFEST_BASENAMES.has(basename.toLowerCase())) return "manifest";
  const dot = basename.lastIndexOf(".");
  if (dot <= 0 || dot === basename.length - 1) return null;
  return EXTENSION_LANGUAGE[basename.slice(dot).toLowerCase()] ?? null;
}

// True when any directory segment (every segment except the file basename)
// is a generated directory. Call only with normalized names.
export function isExcludedPath(normalized: string): boolean {
  const segments = normalized.split("/");
  for (let i = 0; i < segments.length - 1; i += 1) {
    if (EXCLUDED_DIR_SEGMENTS.has(segments[i]!)) return true;
  }
  return false;
}

export function isBinary(bytes: Uint8Array): boolean {
  const probe = Math.min(bytes.length, BINARY_PROBE_BYTES);
  for (let i = 0; i < probe; i += 1) {
    if (bytes[i] === 0) return true;
  }
  return false;
}

export function displayName(raw: string): string {
  return raw.slice(0, 80) || "(empty name)";
}
