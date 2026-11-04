export type OnlineErrorCode =
  | "invalid-url"
  | "blocked-host"
  | "dns-failed"
  | "too-many-redirects"
  | "fetch-failed"
  | "fetch-timeout"
  | "too-large"
  | "not-html"
  | "busy";

const STATUS: Record<OnlineErrorCode, number> = {
  "invalid-url": 400,
  "blocked-host": 400,
  "dns-failed": 502,
  "too-many-redirects": 502,
  "fetch-failed": 502,
  "fetch-timeout": 504,
  "too-large": 413,
  "not-html": 415,
  busy: 429,
};

export class OnlineError extends Error {
  readonly code: OnlineErrorCode;
  readonly status: number;

  constructor(code: OnlineErrorCode, message: string) {
    super(message);
    this.name = "OnlineError";
    this.code = code;
    this.status = STATUS[code];
  }
}
