import { strFromU8 } from "fflate";
import { IntakeError } from "./errors.js";
import { classifyBasename, isExcludedPath, normalizeEntryName } from "./classify.js";
import { MAX_EXTRACTED_BYTES, MAX_FILES, MAX_FILE_BYTES } from "./limits.js";

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;
const ZIP64_PLACEHOLDER_16 = 0xffff;
const ZIP64_PLACEHOLDER_32 = 0xffffffff;

export interface CentralDirectoryInfo {
  entryCount: number;
  // Sum of claimed uncompressed sizes for entries that will actually be
  // inflated (path-safe, non-excluded, recognized type). Entries skipped
  // without inflation contribute nothing because they cost no output bytes.
  claimedExtractedBytes: number;
  candidateCount: number;
}

// Strict, fail-closed central-directory validation. Every anomaly throws —
// malformed structures are rejected here and NEVER fall through to
// best-effort extraction. Size claims are used only for early rejection;
// the streaming inflater re-enforces every byte it actually produces, so
// lying-small claims cannot bypass the caps.
export function validateZipStructure(data: Uint8Array): CentralDirectoryInfo {
  const size = data.byteLength;
  if (size < 22) {
    throw new IntakeError("not-a-zip", "archive is too small to be a ZIP file");
  }
  const view = new DataView(data.buffer, data.byteOffset, size);

  // Locate the end-of-central-directory record, verifying the comment length
  // so a coincidental signature inside file data is not accepted.
  let eocd = -1;
  const scanStart = Math.max(0, size - 22 - 65535);
  for (let i = size - 22; i >= scanStart; i -= 1) {
    if (view.getUint32(i, true) !== EOCD_SIG) continue;
    const commentLen = view.getUint16(i + 20, true);
    if (i + 22 + commentLen === size) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) {
    throw new IntakeError("not-a-zip", "end of central directory not found");
  }

  const diskNum = view.getUint16(eocd + 4, true);
  const cdDisk = view.getUint16(eocd + 6, true);
  const diskEntries = view.getUint16(eocd + 8, true);
  const totalEntries = view.getUint16(eocd + 10, true);
  const cdSize = view.getUint32(eocd + 12, true);
  const cdOffset = view.getUint32(eocd + 16, true);

  if (diskNum !== 0 || cdDisk !== 0 || diskEntries !== totalEntries) {
    throw new IntakeError("unsupported-format", "multi-disk archives are not supported");
  }
  if (
    totalEntries === ZIP64_PLACEHOLDER_16 ||
    cdSize === ZIP64_PLACEHOLDER_32 ||
    cdOffset === ZIP64_PLACEHOLDER_32
  ) {
    throw new IntakeError("unsupported-format", "zip64 archives are not supported");
  }
  if (eocd >= 20 && view.getUint32(eocd - 20, true) === ZIP64_LOCATOR_SIG) {
    throw new IntakeError("unsupported-format", "zip64 archives are not supported");
  }
  if (totalEntries > MAX_FILES) {
    throw new IntakeError(
      "too-many-files",
      `archive declares ${totalEntries} entries, limit is ${MAX_FILES}`
    );
  }
  if (cdOffset + cdSize > size) {
    throw new IntakeError("not-a-zip", "central directory extends beyond end of archive");
  }

  let pos = cdOffset;
  let claimedTotal = 0;
  let candidates = 0;
  for (let n = 0; n < totalEntries; n += 1) {
    if (pos + 46 > size) {
      throw new IntakeError("not-a-zip", "truncated central directory");
    }
    if (view.getUint32(pos, true) !== CD_SIG) {
      throw new IntakeError("not-a-zip", `malformed central directory entry ${n}`);
    }
    const flags = view.getUint16(pos + 8, true);
    const method = view.getUint16(pos + 10, true);
    const compressed = view.getUint32(pos + 20, true);
    const uncompressed = view.getUint32(pos + 24, true);
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    const localOffset = view.getUint32(pos + 42, true);
    if (pos + 46 + nameLen + extraLen + commentLen > size) {
      throw new IntakeError("not-a-zip", `truncated central directory entry ${n}`);
    }
    if (compressed === ZIP64_PLACEHOLDER_32 || uncompressed === ZIP64_PLACEHOLDER_32) {
      throw new IntakeError("unsupported-format", "zip64 entries are not supported");
    }
    if ((flags & 0x1) !== 0) {
      throw new IntakeError("unsupported-format", "encrypted archives are not supported");
    }
    if (method !== 0 && method !== 8) {
      throw new IntakeError("unsupported-format", `unsupported compression method ${method}`);
    }
    if (localOffset + 30 > size) {
      throw new IntakeError("not-a-zip", `local header offset out of range for entry ${n}`);
    }

    // Only entries that will actually be inflated count toward the claimed
    // totals. Anything skipped without inflation costs no output bytes, so
    // its claims are irrelevant (and cannot trigger false rejections).
    const rawName = strFromU8(data.subarray(pos + 46, pos + 46 + nameLen));
    const normalized = normalizeEntryName(rawName);
    if (normalized !== null && !rawName.endsWith("/") && !isExcludedPath(normalized)) {
      const basename = normalized.slice(normalized.lastIndexOf("/") + 1);
      if (classifyBasename(basename) !== null) {
        candidates += 1;
        if (uncompressed > MAX_FILE_BYTES) {
          throw new IntakeError(
            "extracted-too-large",
            `entry "${normalized.slice(0, 80)}" declares ${uncompressed} bytes, ` +
              `per-file limit is ${MAX_FILE_BYTES}`
          );
        }
        claimedTotal += uncompressed;
        if (claimedTotal > MAX_EXTRACTED_BYTES) {
          throw new IntakeError(
            "extracted-too-large",
            `archive declares more than ${MAX_EXTRACTED_BYTES} extracted bytes`
          );
        }
      }
    }
    pos += 46 + nameLen + extraLen + commentLen;
  }

  if (pos !== cdOffset + cdSize) {
    throw new IntakeError("not-a-zip", "central directory size mismatch");
  }
  return { entryCount: totalEntries, claimedExtractedBytes: claimedTotal, candidateCount: candidates };
}
