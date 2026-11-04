export type IntakeRejectCode =
  | "too-large"
  | "not-a-zip"
  | "too-many-files"
  | "extracted-too-large"
  | "unsupported-format";

export class IntakeError extends Error {
  readonly code: IntakeRejectCode;
  readonly status: number;

  constructor(code: IntakeRejectCode, message: string) {
    super(message);
    this.name = "IntakeError";
    this.code = code;
    this.status = code === "too-large" || code === "extracted-too-large" ? 413 : 400;
  }
}
