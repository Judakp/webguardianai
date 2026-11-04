// Central limits for the Online Site pipeline. Every fetch, redirect hop,
// DNS lookup, and response body is bounded here so one hostile or enormous
// site cannot exhaust server memory, sockets, or time.
export const ONLINE_MAX_URL_CHARS = 2048;
export const ONLINE_MAX_REDIRECTS = 5;
export const ONLINE_FETCH_TIMEOUT_MS = 10_000;
export const ONLINE_DNS_TIMEOUT_MS = 10_000;
export const ONLINE_OVERALL_TIMEOUT_MS = 120_000;
export const ONLINE_MAX_BODY_BYTES = 2 * 1024 * 1024;
export const ONLINE_MAX_CONCURRENT_ANALYSES = 4;
// Longest gap allowed between response body chunks. A slow-drip server
// must not consume the full overall budget one byte at a time.
export const ONLINE_BODY_IDLE_TIMEOUT_MS = 15_000;

// Evidence caps: lists keep a bounded sample plus a total so reports stay
// small no matter how large the page is.
export const ONLINE_MAX_EVIDENCE_ITEMS = 50;
export const ONLINE_MAX_TEXT_CHARS = 500;
export const ONLINE_MAX_EVIDENCE_CHARS = 300;

export const ONLINE_USER_AGENT = "WebGuardianAI/0.1 (+security-inspection)";

// Playwright browser inspection limits.
export const BROWSER_NAVIGATION_TIMEOUT_MS = 25_000;
export const BROWSER_TOTAL_TIMEOUT_MS = 40_000;
export const BROWSER_MAX_REQUESTS = 40;
export const BROWSER_MAX_TOTAL_BYTES = 8 * 1024 * 1024;
export const BROWSER_MAX_RESOURCE_BYTES = 1024 * 1024;
export const BROWSER_MAX_REDIRECTS = 5;
