import type { Finding, FindingCategory, FindingConfidence, Severity } from "webguardian-shared";
import { ONLINE_MAX_EVIDENCE_CHARS } from "./limits.js";
import type { SiteEvidence } from "./extract.js";

// Deterministic static checks over collected website evidence. Every finding
// quotes the evidence it is based on; nothing is inferred beyond what was
// observed. Checks that cannot be performed (no data) are reported as
// info-level "not evaluated" notes instead of failures. These are static
// checks, not AI reasoning.

function quote(value: string): string {
  const single = value.replace(/\s+/g, " ").trim();
  return single.length > ONLINE_MAX_EVIDENCE_CHARS
    ? `${single.slice(0, ONLINE_MAX_EVIDENCE_CHARS)}…`
    : single;
}

interface FindingDetail {
  category: FindingCategory;
  description: string;
  whyItMatters: string;
  confidence: FindingConfidence;
}

// Static metadata per check id. Descriptions state what was observed in
// general terms; the per-finding evidence field carries the actual quotes.
const DETAILS: Record<string, FindingDetail> = {
  "transport-plain-http": {
    category: "Security",
    description: "The final page URL uses plain HTTP, so traffic is unencrypted.",
    whyItMatters: "Attackers on the network can read or modify everything sent to and from the site.",
    confidence: "high",
  },
  "transport-upgrades-to-https": {
    category: "Security",
    description: "An HTTP request was redirected to an HTTPS URL.",
    whyItMatters: "Automatic upgrades protect visitors who type or follow plain-HTTP links.",
    confidence: "high",
  },
  "transport-https": {
    category: "Security",
    description: "The final page URL uses HTTPS.",
    whyItMatters: "Encryption in transit protects content and credentials from eavesdropping.",
    confidence: "high",
  },
  "hsts-not-evaluated": {
    category: "Security",
    description: "HSTS could not be evaluated because the page was served over HTTP.",
    whyItMatters: "HSTS only takes effect on HTTPS responses, so HTTP must be fixed first.",
    confidence: "high",
  },
  "hsts-missing": {
    category: "Security",
    description: "The HTTPS response carried no Strict-Transport-Security header.",
    whyItMatters: "Without HSTS, visitors can be downgraded to HTTP on first or manipulated visits.",
    confidence: "high",
  },
  "hsts-weak": {
    category: "Security",
    description: "The HSTS max-age is shorter than 180 days.",
    whyItMatters: "A short max-age leaves long gaps where protection expires between visits.",
    confidence: "high",
  },
  "hsts-enabled": {
    category: "Security",
    description: "A long-lived HSTS policy was observed on the HTTPS response.",
    whyItMatters: "HSTS tells browsers to refuse plain-HTTP connections to the site.",
    confidence: "high",
  },
  "hsts-missing-includesubdomains": {
    category: "Security",
    description: "The HSTS policy does not include the includeSubDomains directive.",
    whyItMatters: "Subdomains stay downgradeable while only the apex host is protected.",
    confidence: "high",
  },
  "csp-missing": {
    category: "Security",
    description: "The response carried no Content-Security-Policy header.",
    whyItMatters: "CSP is the main browser guardrail that limits where scripts and content can load from.",
    confidence: "high",
  },
  "csp-present": {
    category: "Security",
    description: "A Content-Security-Policy header was observed.",
    whyItMatters: "A maintained policy constrains script execution and resource loads.",
    confidence: "high",
  },
  "csp-permissive-script-sources": {
    category: "Security",
    description: "The effective script source list contains wildcard, scheme, or unsafe sources.",
    whyItMatters: "Permissive script sources let injected scripts run, defeating much of the policy.",
    confidence: "high",
  },
  "framing-unprotected": {
    category: "Security",
    description: "Neither X-Frame-Options nor a CSP frame-ancestors directive protects the page.",
    whyItMatters: "Attackers can embed the page in a hidden frame to trick users into clicking (clickjacking).",
    confidence: "high",
  },
  "framing-protected": {
    category: "Security",
    description: "Clickjacking protection was observed via X-Frame-Options or CSP frame-ancestors.",
    whyItMatters: "Framing controls stop other sites from embedding this page without permission.",
    confidence: "high",
  },
  "content-type-options-missing": {
    category: "Security",
    description: "The X-Content-Type-Options: nosniff header is missing or ineffective.",
    whyItMatters: "Without nosniff, browsers may MIME-sniff responses and execute them as scripts.",
    confidence: "high",
  },
  "referrer-policy-missing": {
    category: "Best practices",
    description: "The response carried no Referrer-Policy header.",
    whyItMatters: "An explicit policy limits how much of the page URL leaks to other sites.",
    confidence: "high",
  },
  "cookies-not-evaluated": {
    category: "Security",
    description: "No Set-Cookie headers were observed, so cookie flags could not be checked.",
    whyItMatters: "Cookie flags only matter when the site actually sets cookies.",
    confidence: "high",
  },
  "cookie-missing-secure": {
    category: "Security",
    description: "A cookie set over HTTPS lacks the Secure flag.",
    whyItMatters: "Without Secure, the browser may send the cookie over plain HTTP where it can be stolen.",
    confidence: "high",
  },
  "cookie-missing-httponly": {
    category: "Security",
    description: "A cookie lacks the HttpOnly flag.",
    whyItMatters: "Without HttpOnly, injected scripts can read the cookie value.",
    confidence: "high",
  },
  "cookie-missing-samesite": {
    category: "Security",
    description: "A cookie has no SameSite attribute.",
    whyItMatters: "Without SameSite, the cookie is sent on cross-site requests, aiding CSRF attacks.",
    confidence: "high",
  },
  "server-version-disclosed": {
    category: "Technical",
    description: "Response headers disclose server software or version details.",
    whyItMatters: "Version strings help attackers pick exploits for known vulnerabilities.",
    confidence: "high",
  },
  "mixed-content-not-evaluated": {
    category: "Security",
    description: "Mixed content could not be evaluated for this page.",
    whyItMatters: "The check only applies to HTTPS pages with observable subresources.",
    confidence: "high",
  },
  "mixed-content-http-subresource": {
    category: "Security",
    description: "An HTTPS page loads a script, stylesheet, or frame over plain HTTP.",
    whyItMatters: "HTTP subresources can be modified in transit and undermine the secure page.",
    confidence: "high",
  },
  "forms-not-evaluated": {
    category: "Security",
    description: "No form elements were found, so form checks could not run.",
    whyItMatters: "Form submission risks only exist where forms are present.",
    confidence: "high",
  },
  "password-form-over-http": {
    category: "Security",
    description: "A form containing a password field submits to an HTTP URL.",
    whyItMatters: "Credentials submitted over HTTP can be intercepted directly.",
    confidence: "high",
  },
  "password-form-https": {
    category: "Security",
    description: "A form containing a password field submits over HTTPS.",
    whyItMatters: "Encrypted submission protects credentials in transit.",
    confidence: "high",
  },
  "password-forms-not-evaluated": {
    category: "Security",
    description: "Forms were found but none contain a password field.",
    whyItMatters: "Credential-submission checks only apply to password forms.",
    confidence: "high",
  },
  "form-submits-over-http": {
    category: "Security",
    description: "A form without password fields submits to an HTTP URL.",
    whyItMatters: "Form data sent over HTTP can be read or altered in transit.",
    confidence: "high",
  },
  "inline-event-handlers": {
    category: "Security",
    description: "Elements use inline event-handler attributes such as onclick.",
    whyItMatters: "Inline handlers force a permissive CSP and make injected handlers harder to block.",
    confidence: "high",
  },
  "javascript-href": {
    category: "Best practices",
    description: "Links use javascript: URLs instead of buttons and event listeners.",
    whyItMatters: "javascript: URLs complicate CSP enforcement and degrade accessibility.",
    confidence: "high",
  },
  "blank-without-noopener": {
    category: "Security",
    description: "New-tab links lack rel=noopener.",
    whyItMatters: "Without noopener, the opened page can manipulate the opener (reverse tabnabbing).",
    confidence: "high",
  },
  "script-missing-sri": {
    category: "Security",
    description: "Cross-origin scripts load without subresource-integrity hashes.",
    whyItMatters: "Without SRI, a compromised CDN can silently change the code your visitors run.",
    confidence: "high",
  },
  "render-blocking-scripts": {
    category: "Performance",
    description: "External scripts load without async or defer.",
    whyItMatters: "Synchronous scripts delay page rendering and interaction.",
    confidence: "high",
  },
  "images-missing-alt": {
    category: "Accessibility",
    description: "Some images have no alt text.",
    whyItMatters: "Screen-reader users and search engines rely on alt text to understand images.",
    confidence: "high",
  },
  "html-lang-missing": {
    category: "Accessibility",
    description: "The html element has no lang attribute.",
    whyItMatters: "Assistive technology uses the language to pronounce content correctly.",
    confidence: "high",
  },
  "title-missing": {
    category: "SEO",
    description: "No title element was found.",
    whyItMatters: "The title is the primary label shown in tabs and search results.",
    confidence: "high",
  },
  "title-too-long": {
    category: "SEO",
    description: "The title element is longer than about 60 characters.",
    whyItMatters: "Overlong titles are truncated in search results and dilute the message.",
    confidence: "high",
  },
  "meta-description-missing": {
    category: "SEO",
    description: "No meta description was found.",
    whyItMatters: "Search engines often show the meta description as the result snippet.",
    confidence: "high",
  },
  "meta-description-too-long": {
    category: "SEO",
    description: "The meta description is longer than about 160 characters.",
    whyItMatters: "Overlong descriptions are truncated in search result snippets.",
    confidence: "high",
  },
  "canonical-missing": {
    category: "SEO",
    description: "No canonical link was found.",
    whyItMatters: "A canonical URL tells search engines which address is the authoritative one.",
    confidence: "high",
  },
  "robots-directives": {
    category: "SEO",
    description: "A robots meta tag with crawler directives was observed.",
    whyItMatters: "noindex or nofollow directives change whether the page appears in search results.",
    confidence: "high",
  },
  "h1-missing": {
    category: "SEO",
    description: "No h1 heading was found.",
    whyItMatters: "A single h1 gives the page a clear primary topic for readers and crawlers.",
    confidence: "high",
  },
  "multiple-h1": {
    category: "SEO",
    description: "More than one h1 heading was found.",
    whyItMatters: "Multiple h1s blur which heading is the primary topic of the page.",
    confidence: "high",
  },
  "heading-order-skipped": {
    category: "Accessibility",
    description: "Heading levels skip (for example h1 followed directly by h3).",
    whyItMatters: "Skipped levels confuse screen-reader navigation through the document outline.",
    confidence: "high",
  },
  "suspicious-links": {
    category: "Security",
    description: "Some links show structural signals that merit human review.",
    whyItMatters: "Credentials in URLs, IP hosts, punycode, or mismatched link text are common in phishing.",
    confidence: "medium",
  },
  "links-live-check-not-evaluated": {
    category: "Technical",
    description: "Link destinations were not fetched, so broken links were not verified.",
    whyItMatters: "Verifying every link requires extra requests; none were made beyond the page itself.",
    confidence: "high",
  },
  "link-broken": {
    category: "SEO",
    description: "A sampled link destination failed verification.",
    whyItMatters: "Broken links harm navigation, credibility, and search indexing.",
    confidence: "high",
  },
  "links-verified": {
    category: "SEO",
    description: "Sampled link destinations were verified for reachability.",
    whyItMatters: "Verified links confirm the sampled destinations currently resolve.",
    confidence: "high",
  },
};

function finding(
  id: string,
  title: string,
  severity: Severity,
  evidence: string,
  recommendation: string
): Finding {
  const detail = DETAILS[id] ?? {
    category: "Technical" as FindingCategory,
    description: title,
    whyItMatters: recommendation,
    confidence: "medium" as FindingConfidence,
  };
  return {
    id,
    title,
    severity,
    category: detail.category,
    description: detail.description,
    whyItMatters: detail.whyItMatters,
    confidence: detail.confidence,
    evidence: quote(evidence),
    recommendation,
  };
}

// Removes exact-duplicate findings (same check, title, and evidence) while
// keeping the deterministic check order. Per-instance findings such as
// per-cookie flags differ by title or evidence and are preserved.
export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const item of findings) {
    const key = `${item.id}\n${item.title}\n${item.evidence ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function header(evidence: SiteEvidence, name: string): string | null {
  const value = evidence.headers[name];
  return value === undefined || value === "" ? null : value;
}

// Sources that materially weaken script protection when they appear in the
// effective script directive (script-src, falling back to default-src).
const RISKY_SCRIPT_TOKENS = new Set(["*", "data:", "blob:", "http:", "https:", "'unsafe-eval'"]);

function riskyScriptSources(
  csp: string
): { directive: string; sources: string; risky: string[] } | null {
  const directives = new Map<string, string[]>();
  for (const part of csp.split(";")) {
    const tokens = part.trim().split(/\s+/).filter((t) => t !== "");
    if (tokens.length === 0) continue;
    const name = tokens[0]!.toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1));
  }
  const scriptSrc = directives.get("script-src");
  const fallback = directives.get("default-src");
  const effective = scriptSrc ?? fallback;
  const directive = scriptSrc !== undefined ? "script-src" : "default-src";
  if (!effective || effective.length === 0) return null;
  const lowered = effective.map((s) => s.toLowerCase());
  // 'unsafe-inline' is ignored by modern browsers when a nonce or hash source
  // is present, so it only counts as risky without one.
  const hasNonceOrHash = lowered.some(
    (s) => s.startsWith("'nonce-") || s.startsWith("'sha256-") || s.startsWith("'sha384-") || s.startsWith("'sha512-")
  );
  const risky = effective.filter((s) => {
    const low = s.toLowerCase();
    if (RISKY_SCRIPT_TOKENS.has(low)) return true;
    return low === "'unsafe-inline'" && !hasNonceOrHash;
  });
  if (risky.length === 0) return null;
  return { directive, sources: effective.join(" "), risky };
}

export function runOnlineChecks(evidence: SiteEvidence): Finding[] {
  const findings: Finding[] = [];
  const https = evidence.finalIsHttps;

  // ---- Transport ----
  if (!https) {
    findings.push(
      finding(
        "transport-plain-http",
        "Site served over plain HTTP",
        "high",
        `Final URL: ${evidence.finalUrl}`,
        "Serve the site over HTTPS, redirect all HTTP traffic to HTTPS, and enable HSTS once HTTPS works."
      )
    );
  } else if (evidence.startUrl.startsWith("http://")) {
    findings.push(
      finding(
        "transport-upgrades-to-https",
        "HTTP requests upgrade to HTTPS",
        "info",
        `Requested ${evidence.startUrl} → served ${evidence.finalUrl}`,
        "Keep the HTTP→HTTPS redirect and consider HSTS preloading for full coverage."
      )
    );
  } else {
    findings.push(
      finding(
        "transport-https",
        "Site served over HTTPS",
        "info",
        `Final URL: ${evidence.finalUrl}`,
        "No action needed for transport encryption."
      )
    );
  }

  // ---- HSTS ----
  const hsts = header(evidence, "strict-transport-security");
  if (!https) {
    findings.push(
      finding(
        "hsts-not-evaluated",
        "HSTS not evaluated (requires HTTPS)",
        "info",
        "Page was served over plain HTTP, where HSTS has no effect.",
        "Enable HTTPS first, then send Strict-Transport-Security."
      )
    );
  } else if (hsts === null) {
    findings.push(
      finding(
        "hsts-missing",
        "HSTS header missing",
        "medium",
        `No strict-transport-security header on ${evidence.finalUrl}`,
        'Send "Strict-Transport-Security: max-age=31536000; includeSubDomains" on all HTTPS responses.'
      )
    );
  } else {
    const maxAge = /max-age\s*=\s*(\d+)/i.exec(hsts);
    const seconds = maxAge ? Number(maxAge[1]) : 0;
    if (seconds < 15552000) {
      findings.push(
        finding(
          "hsts-weak",
          "HSTS max-age is short",
          "low",
          `strict-transport-security: ${hsts}`,
          "Raise max-age to at least 15552000 (180 days) and add includeSubDomains."
        )
      );
    } else {
      findings.push(
        finding(
          "hsts-enabled",
          "HSTS enabled",
          "info",
          `strict-transport-security: ${hsts}`,
          "No action needed."
        )
      );
      if (!/includeSubDomains/i.test(hsts)) {
        findings.push(
          finding(
            "hsts-missing-includesubdomains",
            "HSTS does not cover subdomains",
            "low",
            `strict-transport-security: ${hsts}`,
            "Add includeSubDomains so subdomains are protected too (and consider preload once ready)."
          )
        );
      }
    }
  }

  // ---- Content Security Policy ----
  const csp = header(evidence, "content-security-policy");
  if (csp === null) {
    findings.push(
      finding(
        "csp-missing",
        "Content-Security-Policy header missing",
        "medium",
        `No content-security-policy header on ${evidence.finalUrl}`,
        "Deploy a Content-Security-Policy (start with report-only) to constrain scripts, frames, and network loads."
      )
    );
  } else {
    findings.push(
      finding(
        "csp-present",
        "Content-Security-Policy present",
        "info",
        `content-security-policy: ${csp}`,
        "Keep the policy tight; avoid unsafe-inline and unsafe-eval where possible."
      )
    );
    const risky = riskyScriptSources(csp);
    if (risky !== null) {
      findings.push(
        finding(
          "csp-permissive-script-sources",
          "Content-Security-Policy allows risky script sources",
          "medium",
          `${risky.directive}: ${risky.sources} (risky: ${risky.risky.join(", ")})`,
          "Remove permissive script sources (wildcards, scheme sources, unsafe-inline/unsafe-eval) so the policy can actually block injected scripts."
        )
      );
    }
  }

  // ---- Clickjacking ----
  const xfo = header(evidence, "x-frame-options");
  // Only DENY and SAMEORIGIN have a protective effect; any other value
  // (including legacy ALLOW-FROM or garbage) leaves the page unprotected.
  const xfoValid = xfo !== null && /^(deny|sameorigin)$/i.test(xfo.trim());
  const frameAncestors = csp !== null && /(^|;)\s*frame-ancestors\s+/i.test(csp);
  if (!xfoValid && !frameAncestors) {
    findings.push(
      finding(
        "framing-unprotected",
        "No clickjacking protection",
        "medium",
        xfo !== null
          ? `x-frame-options: ${xfo} is not protective (use DENY or SAMEORIGIN); no CSP frame-ancestors on ${evidence.finalUrl}`
          : `Neither x-frame-options nor a CSP frame-ancestors directive observed on ${evidence.finalUrl}`,
        'Send "X-Frame-Options: DENY" (or SAMEORIGIN) or a CSP frame-ancestors directive.'
      )
    );
  } else {
    findings.push(
      finding(
        "framing-protected",
        "Clickjacking protection present",
        "info",
        xfoValid ? `x-frame-options: ${xfo}` : "CSP frame-ancestors directive present",
        "No action needed."
      )
    );
  }

  // ---- MIME sniffing ----
  const xcto = header(evidence, "x-content-type-options");
  if (xcto === null || xcto.toLowerCase() !== "nosniff") {
    findings.push(
      finding(
        "content-type-options-missing",
        "X-Content-Type-Options header missing",
        "low",
        `No effective x-content-type-options header on ${evidence.finalUrl}`,
        'Send "X-Content-Type-Options: nosniff" to block MIME-sniffing attacks.'
      )
    );
  }

  // ---- Referrer policy ----
  if (header(evidence, "referrer-policy") === null) {
    findings.push(
      finding(
        "referrer-policy-missing",
        "Referrer-Policy header missing",
        "info",
        `No referrer-policy header on ${evidence.finalUrl}`,
        'Consider "Referrer-Policy: strict-origin-when-cross-origin" to limit URL leakage.'
      )
    );
  }

  // ---- Cookies ----
  if (evidence.setCookies.length === 0) {
    findings.push(
      finding(
        "cookies-not-evaluated",
        "Cookie checks not evaluated (no cookies observed)",
        "info",
        "The response set no cookies.",
        "No action needed unless the site should be setting session cookies."
      )
    );
  } else {
    for (const cookie of evidence.setCookies) {
      const name = cookie.split(";")[0]?.split("=")[0]?.trim() || "(unnamed)";
      const lower = cookie.toLowerCase();
      if (https && !/;\s*secure(\s|;|$)/.test(lower)) {
        findings.push(
          finding(
            "cookie-missing-secure",
            `Cookie "${name}" missing Secure flag`,
            "medium",
            quote(cookie),
            "Add the Secure flag so the cookie is never sent over plain HTTP."
          )
        );
      }
      if (!/;\s*httponly(\s|;|$)/.test(lower)) {
        findings.push(
          finding(
            "cookie-missing-httponly",
            `Cookie "${name}" missing HttpOnly flag`,
            "low",
            quote(cookie),
            "Add HttpOnly unless JavaScript genuinely needs to read this cookie."
          )
        );
      }
      if (!/;\s*samesite\s*=/i.test(cookie)) {
        findings.push(
          finding(
            "cookie-missing-samesite",
            `Cookie "${name}" missing SameSite attribute`,
            "low",
            quote(cookie),
            "Set SameSite=Lax (or Strict) to reduce cross-site request forgery exposure."
          )
        );
      }
    }
  }

  // ---- Server disclosure ----
  const server = header(evidence, "server");
  const poweredBy = header(evidence, "x-powered-by");
  if ((server !== null && /\d/.test(server)) || poweredBy !== null) {
    const parts = [
      server !== null ? `server: ${server}` : "",
      poweredBy !== null ? `x-powered-by: ${poweredBy}` : "",
    ].filter((p) => p !== "");
    findings.push(
      finding(
        "server-version-disclosed",
        "Server technology disclosed in headers",
        "info",
        parts.join("; "),
        "Hide version details to make targeted exploitation slightly harder."
      )
    );
  }

  // ---- Mixed content ----
  if (!https) {
    findings.push(
      finding(
        "mixed-content-not-evaluated",
        "Mixed-content check not evaluated (page itself is HTTP)",
        "info",
        "Mixed content only applies to HTTPS pages.",
        "Enable HTTPS first; this check then applies automatically."
      )
    );
  } else if (evidence.subresourceHttpTotal === 0) {
    findings.push(
      finding(
        "mixed-content-not-evaluated",
        "Mixed-content check not evaluated (no subresources observed)",
        "info",
        "No script, stylesheet, or frame subresources were found to compare.",
        "No action needed."
      )
    );
  } else {
    for (const href of evidence.subresourceHttp) {
      findings.push(
        finding(
          "mixed-content-http-subresource",
          "HTTPS page loads a subresource over HTTP",
          "high",
          href,
          "Load every subresource over HTTPS; browsers block or degrade HTTP loads on secure pages."
        )
      );
    }
  }

  // ---- Forms ----
  if (evidence.formTotal === 0) {
    findings.push(
      finding(
        "forms-not-evaluated",
        "Form checks not evaluated (no forms found)",
        "info",
        "The page contains no <form> elements.",
        "No action needed."
      )
    );
  } else {
    for (const form of evidence.forms) {
      if (!form.hasPassword) continue;
      if (form.http) {
        findings.push(
          finding(
            "password-form-over-http",
            "Password form submits over plain HTTP",
            "high",
            `Form action: ${form.action}`,
            "Submit credentials over HTTPS only; never post passwords to an http:// URL."
          )
        );
      } else {
        findings.push(
          finding(
            "password-form-https",
            "Password form submits over HTTPS",
            "info",
            `Form action: ${form.action}`,
            "Keep credential submission on HTTPS."
          )
        );
      }
    }
    if (!evidence.forms.some((f) => f.hasPassword)) {
      findings.push(
        finding(
          "password-forms-not-evaluated",
          "No password fields observed",
          "info",
          `${evidence.formTotal} form(s) found, none with a password input.`,
          "No action needed."
        )
      );
    }
    const httpForms = evidence.forms.filter((f) => f.http && !f.hasPassword);
    if (httpForms.length > 0) {
      findings.push(
        finding(
          "form-submits-over-http",
          "Forms submit over plain HTTP",
          "low",
          `${httpForms.length} form(s), e.g. ${httpForms
            .slice(0, 3)
            .map((f) => f.action)
            .join(" | ")}`,
          "Submit forms over HTTPS so entered data cannot be read in transit."
        )
      );
    }
  }

  // ---- Inline handlers ----
  if (evidence.inlineHandlerCount > 0) {
    findings.push(
      finding(
        "inline-event-handlers",
        "Inline event handlers present",
        "low",
        `${evidence.inlineHandlerCount} element(s) use inline handlers, e.g. ${evidence.inlineHandlerSample.join(" | ")}`,
        "Move behavior to external scripts so a strict Content-Security-Policy can block injected handlers."
      )
    );
  }
  if (evidence.jsHrefCount > 0) {
    findings.push(
      finding(
        "javascript-href",
        "javascript: links present",
        "low",
        `${evidence.jsHrefCount} link(s), e.g. ${evidence.jsHrefSample.join(" | ")}`,
        "Replace javascript: URLs with buttons and event listeners."
      )
    );
  }

  // ---- Reverse tabnabbing ----
  const riskyBlanks = evidence.links.filter((l) => l.targetBlank && !l.rel.includes("noopener"));
  if (riskyBlanks.length > 0) {
    findings.push(
      finding(
        "blank-without-noopener",
        "New-tab links missing rel=noopener",
        "low",
        `${riskyBlanks.length} link(s), e.g. ${riskyBlanks
          .slice(0, 3)
          .map((l) => l.href)
          .join(" | ")}`,
        'Add rel="noopener" to target="_blank" links to prevent reverse tabnabbing.'
      )
    );
  }

  // ---- Subresource integrity ----
  const crossOriginNoSri = evidence.scripts.filter(
    (s) => s.src !== null && s.external && !s.integrity
  );
  if (crossOriginNoSri.length > 0) {
    findings.push(
      finding(
        "script-missing-sri",
        "Cross-origin scripts without integrity hashes",
        "low",
        `${crossOriginNoSri.length} script(s), e.g. ${crossOriginNoSri
          .slice(0, 3)
          .map((s) => s.src)
          .join(" | ")}`,
        "Add subresource-integrity hashes (with crossorigin) to third-party scripts."
      )
    );
  }

  // ---- Render-blocking scripts ----
  const blocking = evidence.scripts.filter((s) => s.src !== null && !s.async && !s.defer);
  if (blocking.length > 0) {
    findings.push(
      finding(
        "render-blocking-scripts",
        "Scripts may block rendering",
        "low",
        `${blocking.length} external script(s) without async or defer, e.g. ${blocking
          .slice(0, 3)
          .map((s) => s.src)
          .join(" | ")}`,
        "Add async or defer to scripts that do not need to run before rendering."
      )
    );
  }

  // ---- Link review ----
  const suspicious = evidence.suspiciousLinks ?? [];
  if (suspicious.length > 0) {
    findings.push(
      finding(
        "suspicious-links",
        "Links worth a human review",
        "low",
        `${suspicious.length} link(s), e.g. ${suspicious.slice(0, 3).join(" | ")}`,
        "Review these links by hand; this is a structural heuristic, not proof of anything malicious."
      )
    );
  }
  if (evidence.linkChecks !== undefined) {
    const broken = evidence.linkChecks.filter((c) => !c.ok);
    for (const item of broken.slice(0, 10)) {
      findings.push(
        finding(
          "link-broken",
          "Sampled link destination unreachable",
          "low",
          item.status !== undefined ? `${item.href} (HTTP ${item.status})` : item.href,
          "Fix or remove the broken link."
        )
      );
    }
    if (broken.length === 0) {
      findings.push(
        finding(
          "links-verified",
          "Sampled link destinations verified",
          "info",
          `${evidence.linkChecks.length} sampled link(s) verified reachable.`,
          "No action needed."
        )
      );
    }
  } else if (evidence.linkTotal > 0) {
    const internal = evidence.internalLinkTotal ?? 0;
    const external = evidence.externalLinkTotal ?? 0;
    findings.push(
      finding(
        "links-live-check-not-evaluated",
        "Broken-link check not evaluated (destinations not fetched)",
        "info",
        `${evidence.linkTotal} link(s) observed (${internal} internal, ${external} external); no destination was fetched.`,
        "No action needed for this inspection; live verification would require extra requests."
      )
    );
  }

  // ---- Accessibility / basics ----
  if (evidence.imagesMissingAlt > 0) {
    findings.push(
      finding(
        "images-missing-alt",
        "Images missing alt text",
        "info",
        `${evidence.imagesMissingAlt} of ${evidence.imageTotal} image(s), e.g. ${evidence.imageSample.join(" | ")}`,
        "Add descriptive alt text (empty alt only for decorative images)."
      )
    );
  }
  if ((evidence.htmlLang ?? null) === null) {
    findings.push(
      finding(
        "html-lang-missing",
        "Page has no language declaration",
        "info",
        "No lang attribute on the <html> element.",
        'Add a language, e.g. <html lang="en">.'
      )
    );
  }
  if (evidence.title === null) {
    findings.push(
      finding(
        "title-missing",
        "Page has no title",
        "info",
        "No <title> element found.",
        "Add a concise, descriptive <title>."
      )
    );
  } else if (evidence.title.length > 60) {
    findings.push(
      finding(
        "title-too-long",
        "Page title is long",
        "info",
        `Title is ${evidence.title.length} characters: ${evidence.title}`,
        "Keep the title under about 60 characters so it is not truncated."
      )
    );
  }
  if (evidence.metaDescription === null) {
    findings.push(
      finding(
        "meta-description-missing",
        "Page has no meta description",
        "info",
        "No meta name=description found.",
        "Add a one-sentence meta description."
      )
    );
  } else if (evidence.metaDescription.length > 160) {
    findings.push(
      finding(
        "meta-description-too-long",
        "Meta description is long",
        "info",
        `Meta description is ${evidence.metaDescription.length} characters.`,
        "Keep the meta description under about 160 characters."
      )
    );
  }
  if ((evidence.canonical ?? null) === null) {
    findings.push(
      finding(
        "canonical-missing",
        "Page has no canonical URL",
        "info",
        "No link rel=canonical found.",
        "Add a canonical link pointing at the preferred URL for this page."
      )
    );
  }
  const robots = (evidence.robotsMeta ?? "").toLowerCase();
  if (robots.includes("noindex") || robots.includes("nofollow")) {
    findings.push(
      finding(
        "robots-directives",
        "Robots meta restricts crawling or indexing",
        "info",
        `meta name=robots content: ${evidence.robotsMeta}`,
        "Keep these directives only if the page should stay out of search results."
      )
    );
  }

  // ---- Heading hierarchy ----
  const h1Count = evidence.h1Count ?? evidence.headings.filter((h) => h.level === 1).length;
  if (evidence.headingTotal === 0 || h1Count === 0) {
    findings.push(
      finding(
        "h1-missing",
        "Page has no h1 heading",
        "info",
        evidence.headingTotal === 0
          ? "No headings found."
          : `${evidence.headingTotal} heading(s) found, none at level 1.`,
        "Add one h1 that names the primary topic of the page."
      )
    );
  } else if (h1Count > 1) {
    findings.push(
      finding(
        "multiple-h1",
        "Page has multiple h1 headings",
        "low",
        `${h1Count} h1 element(s) found.`,
        "Use a single h1 per page and structure the rest with h2–h6."
      )
    );
  }
  const skips = evidence.headingSkips ?? [];
  if (skips.length > 0) {
    findings.push(
      finding(
        "heading-order-skipped",
        "Heading levels skip",
        "low",
        `Skipped levels observed: ${skips.join(", ")}.`,
        "Nest headings in order without skipping levels."
      )
    );
  }

  return findings;
}
