import { isIP } from "node:net";
import { ONLINE_MAX_EVIDENCE_ITEMS, ONLINE_MAX_TEXT_CHARS } from "./limits.js";
import type { FetchedSite } from "./fetchSite.js";

export interface ExtractedLink {
  href: string;
  text: string;
  external: boolean;
  http: boolean;
  targetBlank: boolean;
  rel: string;
}

export interface ExtractedScript {
  src: string | null;
  external: boolean;
  http: boolean;
  async: boolean;
  defer: boolean;
  integrity: boolean;
}

export interface ExtractedForm {
  action: string;
  external: boolean;
  http: boolean;
  method: string;
  hasPassword: boolean;
}

export interface LinkCheck {
  href: string;
  ok: boolean;
  status?: number;
}

export interface SiteEvidence {
  startUrl: string;
  finalUrl: string;
  finalIsHttps: boolean;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  redirectHops: number;
  title: string | null;
  metaDescription: string | null;
  metaCount: number;
  canonical?: string | null;
  robotsMeta?: string | null;
  htmlLang?: string | null;
  headings: Array<{ level: number; text: string }>;
  headingTotal: number;
  h1Count?: number;
  headingSkips?: string[];
  internalLinkTotal?: number;
  externalLinkTotal?: number;
  suspiciousLinks?: string[];
  cssSample?: string[];
  linkChecks?: LinkCheck[];
  links: ExtractedLink[];
  linkTotal: number;
  scripts: ExtractedScript[];
  scriptTotal: number;
  inlineScriptCount: number;
  forms: ExtractedForm[];
  formTotal: number;
  imagesMissingAlt: number;
  imageTotal: number;
  imageSample: string[];
  inlineHandlerCount: number;
  inlineHandlerSample: string[];
  jsHrefCount: number;
  jsHrefSample: string[];
  subresourceHttp: string[];
  subresourceHttpTotal: number;
  stylesheetTotal: number;
}

function capText(value: string): string {
  return value.length > ONLINE_MAX_TEXT_CHARS ? value.slice(0, ONLINE_MAX_TEXT_CHARS) : value;
}

function decodeEntities(value: string): string {
  return value
    .replace(/&#x([0-9a-fA-F]{1,6});/g, (_, hex: string) =>
      String.fromCodePoint(Math.min(Number.parseInt(hex, 16), 0x10ffff))
    )
    .replace(/&#(\d{1,7});/g, (_, dec: string) =>
      String.fromCodePoint(Math.min(Number.parseInt(dec, 10), 0x10ffff))
    )
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&nbsp;/gi, " ");
}

function stripTags(value: string): string {
  return decodeEntities(value.replace(/<[^>]*>/g, "")).replace(/\s+/g, " ").trim();
}

function parseAttributes(tag: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([\w-]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(tag)) !== null) {
    const name = match[1]!.toLowerCase();
    let value = match[2] ?? "";
    if (value.length >= 2 && (value.startsWith('"') || value.startsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(name in attrs)) attrs[name] = decodeEntities(value);
  }
  return attrs;
}

interface ResolvedRef {
  href: string;
  external: boolean;
  http: boolean;
}

function resolveRef(base: URL, ref: string): ResolvedRef | null {
  const trimmed = ref.trim();
  if (trimmed === "") return null;
  if (/^javascript:/i.test(trimmed)) return null;
  if (/^(data|blob|mailto|tel|sms|ftp):/i.test(trimmed)) return null;
  let url: URL;
  try {
    url = new URL(trimmed, base);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  return {
    href: url.href.slice(0, ONLINE_MAX_TEXT_CHARS),
    external: url.host !== base.host,
    http: url.protocol === "http:",
  };
}

// Heuristic link review without any network access: flags only structural
// signals (credentials in URL, literal-IP host, punycode host, link text that
// looks like a different URL). Returns a short reason or null. Never claims a
// link is malicious — only that it merits human review.
function suspiciousReason(href: string, text: string): string | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  if (url.username !== "" || url.password !== "") return "URL contains credentials";
  if (isIP(url.hostname) !== 0) return "link host is a literal IP address";
  if (url.hostname.toLowerCase().includes("xn--")) return "link host uses punycode";
  const textUrl = /^https?:\/\/([^\s/)]+)/i.exec(text.trim());
  if (textUrl && textUrl[1]!.toLowerCase() !== url.host.toLowerCase()) {
    return "link text shows a different address than the href";
  }
  return null;
}

// Dependency-free HTML scan. The page is treated as inert text: scripts and
// styles are located only as tags and their bodies are excluded from all
// further scanning, so markup-looking strings inside JavaScript can never be
// mistaken for page structure. Nothing here executes.
export function extractEvidence(fetched: FetchedSite): SiteEvidence {
  const base = new URL(fetched.finalUrl);
  const finalIsHttps = base.protocol === "https:";

  const noComments = fetched.body.replace(/<!--[\s\S]*?-->/g, "");

  // Script tags: record attributes, then remove whole elements (bodies may
  // contain markup-looking text that must not be scanned).
  const scripts: ExtractedScript[] = [];
  let scriptTotal = 0;
  let inlineScriptCount = 0;
  for (const match of noComments.matchAll(/<script\b([^>]*)>/gi)) {
    scriptTotal += 1;
    const attrs = parseAttributes(match[1] ?? "");
    const srcRaw = attrs.src?.trim() ?? "";
    if (srcRaw === "") {
      inlineScriptCount += 1;
      if (scripts.length < ONLINE_MAX_EVIDENCE_ITEMS) {
        scripts.push({ src: null, external: false, http: false, async: false, defer: false, integrity: false });
      }
      continue;
    }
    const resolved = resolveRef(base, srcRaw);
    if (scripts.length < ONLINE_MAX_EVIDENCE_ITEMS) {
      scripts.push({
        src: resolved?.href ?? srcRaw.slice(0, ONLINE_MAX_TEXT_CHARS),
        external: resolved?.external ?? false,
        http: resolved?.http ?? false,
        async: "async" in attrs,
        defer: "defer" in attrs,
        integrity: "integrity" in attrs,
      });
    }
  }
  const noScripts = noComments.replace(/<script\b[^>]*>[\s\S]*?(<\/script\s*>|$)/gi, "");
  const soup = noScripts.replace(/<style\b[^>]*>[\s\S]*?(<\/style\s*>|$)/gi, "");

  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(soup);
  const title = titleMatch ? stripTags(titleMatch[1] ?? "").slice(0, ONLINE_MAX_TEXT_CHARS) || null : null;

  let metaDescription: string | null = null;
  let robotsMeta: string | null = null;
  let metaCount = 0;
  for (const match of soup.matchAll(/<meta\b([^>]*)>/gi)) {
    metaCount += 1;
    const attrs = parseAttributes(match[1] ?? "");
    const name = (attrs.name ?? attrs.property ?? "").toLowerCase();
    if ((name === "description" || name === "og:description") && metaDescription === null) {
      metaDescription = (attrs.content ?? "").replace(/\s+/g, " ").trim().slice(0, ONLINE_MAX_TEXT_CHARS) || null;
    }
    if (name === "robots" && robotsMeta === null) {
      robotsMeta = (attrs.content ?? "").replace(/\s+/g, " ").trim().slice(0, 200) || null;
    }
  }

  const htmlOpen = /<html\b([^>]*)>/i.exec(noComments);
  const htmlLang = htmlOpen
    ? (parseAttributes(htmlOpen[1] ?? "").lang?.trim().slice(0, 20) || null)
    : null;

  let canonical: string | null = null;
  for (const match of soup.matchAll(/<link\b([^>]*)>/gi)) {
    const attrs = parseAttributes(match[1] ?? "");
    if (!(attrs.rel ?? "").toLowerCase().split(/\s+/).includes("canonical")) continue;
    const raw = attrs.href?.trim() ?? "";
    if (raw === "") continue;
    const resolved = resolveRef(base, raw);
    canonical = resolved?.href ?? raw.slice(0, ONLINE_MAX_TEXT_CHARS);
    break;
  }

  const headings: Array<{ level: number; text: string }> = [];
  let headingTotal = 0;
  let h1Count = 0;
  const headingSkips: string[] = [];
  let prevLevel = 0;
  for (const match of soup.matchAll(/<(h[1-6])\b[^>]*>([\s\S]*?)<\/\1\s*>/gi)) {
    const level = Number(match[1]![1]);
    headingTotal += 1;
    if (level === 1) h1Count += 1;
    if (prevLevel > 0 && level > prevLevel + 1 && headingSkips.length < 5) {
      headingSkips.push(`h${prevLevel} → h${level}`);
    }
    prevLevel = level;
    if (headings.length < ONLINE_MAX_EVIDENCE_ITEMS) {
      headings.push({
        level,
        text: stripTags(match[2] ?? "").slice(0, ONLINE_MAX_TEXT_CHARS),
      });
    }
  }

  const links: ExtractedLink[] = [];
  let linkTotal = 0;
  let jsHrefCount = 0;
  let internalLinkTotal = 0;
  let externalLinkTotal = 0;
  const jsHrefSample: string[] = [];
  const suspiciousLinks: string[] = [];
  for (const match of soup.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi)) {
    linkTotal += 1;
    const attrs = parseAttributes(match[1] ?? "");
    const rawHref = attrs.href?.trim() ?? "";
    if (/^javascript:/i.test(rawHref)) {
      jsHrefCount += 1;
      if (jsHrefSample.length < 5) jsHrefSample.push(rawHref.slice(0, 120));
      continue;
    }
    const resolved = resolveRef(base, rawHref);
    if (!resolved) continue;
    if (resolved.external) externalLinkTotal += 1;
    else internalLinkTotal += 1;
    const linkText = stripTags(match[2] ?? "").slice(0, 120);
    const reason = suspiciousReason(resolved.href, linkText);
    if (reason !== null && suspiciousLinks.length < ONLINE_MAX_EVIDENCE_ITEMS) {
      suspiciousLinks.push(`${resolved.href} (${reason})`.slice(0, ONLINE_MAX_TEXT_CHARS));
    }
    if (links.length < ONLINE_MAX_EVIDENCE_ITEMS) {
      links.push({
        href: resolved.href,
        text: linkText,
        external: resolved.external,
        http: resolved.http,
        targetBlank: (attrs.target ?? "").toLowerCase() === "_blank",
        rel: (attrs.rel ?? "").toLowerCase().slice(0, 120),
      });
    }
  }

  const forms: ExtractedForm[] = [];
  let formTotal = 0;
  for (const match of soup.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)) {
    formTotal += 1;
    const attrs = parseAttributes(match[1] ?? "");
    const inner = match[2] ?? "";
    const rawAction = attrs.action?.trim() ?? "";
    const resolved = rawAction === "" ? null : resolveRef(base, rawAction);
    if (forms.length < ONLINE_MAX_EVIDENCE_ITEMS) {
      forms.push({
        action: resolved?.href ?? (rawAction === "" ? "(same page)" : rawAction.slice(0, ONLINE_MAX_TEXT_CHARS)),
        external: resolved?.external ?? false,
        http: resolved !== null ? resolved.http : !finalIsHttps,
        method: (attrs.method ?? "get").toLowerCase().slice(0, 12),
        hasPassword: /<input\b[^>]*type\s*=\s*["']?password\b/i.test(inner),
      });
    }
  }

  let imageTotal = 0;
  let imagesMissingAlt = 0;
  const imageSample: string[] = [];
  for (const match of soup.matchAll(/<img\b([^>]*)>/gi)) {
    imageTotal += 1;
    const attrs = parseAttributes(match[1] ?? "");
    if (!("alt" in attrs) || attrs.alt!.trim() === "") {
      imagesMissingAlt += 1;
      if (imageSample.length < 5) {
        imageSample.push((attrs.src ?? "(no src)").slice(0, 120));
      }
    }
    if (imageTotal >= 5000) break;
  }

  let inlineHandlerCount = 0;
  const inlineHandlerSample: string[] = [];
  for (const match of soup.matchAll(/<([a-z][a-z0-9]*)\b[^>]*?\son[a-z]+\s*=/gi)) {
    inlineHandlerCount += 1;
    if (inlineHandlerSample.length < 5) {
      inlineHandlerSample.push(`<${match[1]!.toLowerCase()}> ${match[0]!.slice(0, 100)}`);
    }
    if (inlineHandlerCount >= 5000) break;
  }

  // Subresources that load over plain HTTP (mixed content when the page is HTTPS).
  const subresourceHttp: string[] = [];
  let subresourceHttpTotal = 0;
  const noteHttp = (href: string): void => {
    subresourceHttpTotal += 1;
    if (subresourceHttp.length < ONLINE_MAX_EVIDENCE_ITEMS) subresourceHttp.push(href);
  };
  for (const script of scripts) {
    if (script.src && script.http) noteHttp(script.src);
  }
  let stylesheetTotal = 0;
  const cssSample: string[] = [];
  for (const match of soup.matchAll(/<link\b([^>]*)>/gi)) {
    const attrs = parseAttributes(match[1] ?? "");
    const rel = (attrs.rel ?? "").toLowerCase();
    if (!rel.includes("stylesheet") && !rel.includes("preload") && !rel.includes("icon")) continue;
    stylesheetTotal += 1;
    const resolved = resolveRef(base, attrs.href ?? "");
    if (resolved && cssSample.length < ONLINE_MAX_EVIDENCE_ITEMS) cssSample.push(resolved.href);
    if (resolved?.http) noteHttp(resolved.href);
  }
  for (const match of soup.matchAll(/<iframe\b([^>]*)>/gi)) {
    const attrs = parseAttributes(match[1] ?? "");
    const resolved = resolveRef(base, attrs.src ?? "");
    if (resolved?.http) noteHttp(resolved.href);
  }

  return {
    startUrl: fetched.startUrl,
    finalUrl: fetched.finalUrl,
    finalIsHttps,
    status: fetched.status,
    headers: fetched.headers,
    setCookies: fetched.setCookies,
    redirectHops: fetched.redirectHops,
    title,
    metaDescription,
    metaCount,
    canonical,
    robotsMeta,
    htmlLang,
    headings,
    headingTotal,
    h1Count,
    headingSkips,
    links,
    linkTotal,
    internalLinkTotal,
    externalLinkTotal,
    suspiciousLinks,
    scripts,
    scriptTotal,
    inlineScriptCount,
    forms,
    formTotal,
    imagesMissingAlt,
    imageTotal,
    imageSample,
    inlineHandlerCount,
    inlineHandlerSample,
    jsHrefCount,
    jsHrefSample,
    subresourceHttp,
    subresourceHttpTotal,
    stylesheetTotal,
    cssSample,
  };
}

export { capText };
