import { Unzip, UnzipInflate, strFromU8, type UnzipFile } from "fflate";
import type { LanguageId } from "webguardian-shared";
import { IntakeError, type IntakeRejectCode } from "./errors.js";
import {
  classifyBasename,
  displayName,
  isBinary,
  isExcludedPath,
  normalizeEntryName,
} from "./classify.js";
import {
  BINARY_PROBE_BYTES,
  INTAKE_CHUNK_BYTES,
  MAX_ARCHIVE_BYTES,
  MAX_EXTRACTED_BYTES,
  MAX_FILES,
  MAX_FILE_BYTES,
} from "./limits.js";
import { validateZipStructure } from "./zipStruct.js";

export {
  IntakeError,
  type IntakeRejectCode,
  normalizeEntryName,
  MAX_ARCHIVE_BYTES,
  MAX_EXTRACTED_BYTES,
  MAX_FILES,
  MAX_FILE_BYTES,
};

export interface IntakeFile {
  path: string;
  size: number;
  language: LanguageId;
  content: string;
  manifest: boolean;
}

export interface SkippedFile {
  path: string;
  reason:
    | "unsafe-path"
    | "extension"
    | "too-large"
    | "binary"
    | "empty-name"
    | "excluded";
}

export interface IntakeInventory {
  files: IntakeFile[];
  skipped: SkippedFile[];
  archiveBytes: number;
  extractedBytes: number;
}

export interface PublicInventory {
  files: Array<{ path: string; size: number; language: string; manifest: boolean }>;
  skipped: IntakeInventory["skipped"];
  archiveBytes: number;
  extractedBytes: number;
}

// Public responses never carry source contents.
export function toPublicInventory(inventory: IntakeInventory): PublicInventory {
  return {
    files: inventory.files.map((f) => ({
      path: f.path,
      size: f.size,
      language: f.language,
      manifest: f.manifest,
    })),
    skipped: inventory.skipped,
    archiveBytes: inventory.archiveBytes,
    extractedBytes: inventory.extractedBytes,
  };
}

function readUtf8Lossy(bytes: Uint8Array): string {
  return strFromU8(bytes);
}

function mapUnzipError(err: unknown, entry: string): IntakeError {
  const code =
    typeof err === "object" && err !== null && "code" in err
      ? (err as { code?: unknown }).code
      : undefined;
  if (code === 14) {
    return new IntakeError("unsupported-format", "unsupported compression method in archive");
  }
  const where = entry ? ` entry "${entry.slice(0, 80)}"` : "";
  return new IntakeError("not-a-zip", `could not decompress archive${where}`);
}

// Bounded streaming extraction. The archive is fed to the parser in small
// slices; every decompressed chunk is measured the moment it is produced and
// the whole run aborts as soon as any cap is exceeded. Central-directory
// claims are validated first (fail-closed) but are never trusted for
// allocation: actual inflated bytes are authoritative.
//
// skipped entries (unsafe path, excluded directory, unrecognized type) are
// never inflated, so their claims cost nothing. Every inflated candidate
// counts toward the totals, including files later skipped as binary.
// Any candidate exceeding MAX_FILE_BYTES rejects the entire archive.
function runBoundedStream(data: Uint8Array, collectContent: boolean): IntakeInventory {
  validateZipStructure(data);

  const files: IntakeFile[] = [];
  const skipped: SkippedFile[] = [];
  let totalInflated = 0;
  let extractedBytes = 0;
  let seenEntries = 0;
  let failure: IntakeError | null = null;

  const unzipper = new Unzip();
  // Stored entries (method 0) are pre-registered by fflate; deflate needs it.
  unzipper.register(UnzipInflate);
  unzipper.onfile = (file: UnzipFile) => {
    if (failure) return;
    seenEntries += 1;
    if (seenEntries > MAX_FILES) {
      failure = new IntakeError(
        "too-many-files",
        `archive contains more than ${MAX_FILES} entries`
      );
      return;
    }
    const raw = file.name;
    if (raw.endsWith("/")) return;
    const normalized = normalizeEntryName(raw);
    if (!normalized) {
      skipped.push({ path: displayName(raw), reason: raw ? "unsafe-path" : "empty-name" });
      return;
    }
    if (isExcludedPath(normalized)) {
      skipped.push({ path: normalized, reason: "excluded" });
      return;
    }
    const basename = normalized.slice(normalized.lastIndexOf("/") + 1);
    const classification = classifyBasename(basename);
    if (!classification) {
      skipped.push({ path: normalized, reason: "extension" });
      return;
    }

    const chunks: Uint8Array[] = [];
    let keptBytes = 0;
    let fileBytes = 0;
    let finalized = false;
    file.ondata = (err, chunk, final) => {
      if (failure || finalized) return;
      if (err) {
        failure = mapUnzipError(err, normalized);
        return;
      }
      if (chunk && chunk.length > 0) {
        fileBytes += chunk.length;
        if (fileBytes > MAX_FILE_BYTES) {
          failure = new IntakeError(
            "extracted-too-large",
            `entry "${normalized.slice(0, 80)}" exceeds the per-file limit of ` +
              `${MAX_FILE_BYTES} bytes`
          );
          return;
        }
        totalInflated += chunk.length;
        if (totalInflated > MAX_EXTRACTED_BYTES) {
          failure = new IntakeError(
            "extracted-too-large",
            `archive extracts to more than ${MAX_EXTRACTED_BYTES} bytes`
          );
          return;
        }
        // Retained contents are collected only when requested; otherwise the
        // first probe bytes are kept for the binary check and the rest is
        // counted and discarded.
        if (collectContent) {
          chunks.push(chunk);
          keptBytes += chunk.length;
        } else if (keptBytes < BINARY_PROBE_BYTES) {
          const room = BINARY_PROBE_BYTES - keptBytes;
          const slice = chunk.length > room ? chunk.subarray(0, room) : chunk;
          chunks.push(slice);
          keptBytes += slice.length;
        }
      }
      if (final) {
        finalized = true;
        let probe: Uint8Array;
        if (chunks.length === 1) {
          probe = chunks[0]!;
        } else if (chunks.length === 0) {
          probe = new Uint8Array(0);
        } else {
          probe = new Uint8Array(keptBytes);
          let off = 0;
          for (const c of chunks) {
            probe.set(c, off);
            off += c.length;
          }
        }
        if (isBinary(probe)) {
          skipped.push({ path: normalized, reason: "binary" });
          return;
        }
        const content = collectContent ? readUtf8Lossy(probe) : "";
        files.push({
          path: normalized,
          size: fileBytes,
          language: classification === "manifest" ? "unknown" : classification,
          content,
          manifest: classification === "manifest",
        });
        extractedBytes += fileBytes;
      }
    };
    try {
      file.start();
    } catch (err) {
      if (!failure) failure = mapUnzipError(err, normalized);
    }
  };

  try {
    for (let off = 0; off < data.byteLength && !failure; off += INTAKE_CHUNK_BYTES) {
      const end = Math.min(off + INTAKE_CHUNK_BYTES, data.byteLength);
      unzipper.push(data.subarray(off, end), end === data.byteLength);
    }
  } catch (err) {
    if (!failure) failure = mapUnzipError(err, "");
  }
  if (failure) throw failure;

  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  skipped.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { files, skipped, archiveBytes: data.byteLength, extractedBytes };
}

// In-memory bounded extraction. Entries are never written to disk and never
// executed. All reads are bounded by the module caps above. Prefer the worker
// file pipeline for production uploads so large archives never occupy the
// main-thread heap.
export function extractZipSafely(data: Uint8Array): IntakeInventory {
  if (data.byteLength > MAX_ARCHIVE_BYTES) {
    throw new IntakeError(
      "too-large",
      `archive is ${data.byteLength} bytes, limit is ${MAX_ARCHIVE_BYTES}`
    );
  }
  return runBoundedStream(data, true);
}

// Bounded extraction that discards contents and returns only metadata. Used
// by the worker pipeline so the main thread never holds source bytes.
export function extractZipPublicFromBytes(data: Uint8Array): PublicInventory {
  if (data.byteLength > MAX_ARCHIVE_BYTES) {
    throw new IntakeError(
      "too-large",
      `archive is ${data.byteLength} bytes, limit is ${MAX_ARCHIVE_BYTES}`
    );
  }
  return toPublicInventory(runBoundedStream(data, false));
}
