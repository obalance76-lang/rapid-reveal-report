// Deterministic pseudo-analysis engine.
// Hashes the submitted URL so the same site always returns the same report.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  description: string;
  remediation: string;
  cvss: number;
}

export interface ThreatAssessment {
  id: string;
  name: string;
  short: string;
  rating: number; // 0-100 vulnerability to this threat
  verdict: "Vulnerable" | "At Risk" | "Guarded" | "Hardened";
  detail: string;
  attackVectors: string[];
  toolsUsed: string[];
  recommendedTools: string[];
}

export interface ScanReport {
  url: string;
  host: string;
  scannedAt: string;
  mode: "quick" | "deep";
  score: number; // 0-100 security score (higher = safer)
  grade: string;
  findings: Finding[];
  threats: ThreatAssessment[];
  toolsUsed: string[];
  recommendedTools: string[];
}

// ---------- seeded PRNG ----------
function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T,>(r: () => number, arr: T[]): T => arr[Math.floor(r() * arr.length)];

// ---------- finding pools ----------
const FINDING_POOL: Omit<Finding, "id">[] = [
  {
    title: "Missing Content-Security-Policy header",
    category: "HTTP Headers",
    severity: "high",
    description:
      "The response does not define a Content-Security-Policy. Without CSP the browser cannot restrict which scripts, frames or connections the page may use, increasing the impact of any injected content.",
    remediation:
      "Define a restrictive Content-Security-Policy header, starting in report-only mode, then enforce.",
    cvss: 7.1,
  },
  {
    title: "TLS certificate expires within 30 days",
    category: "Transport",
    severity: "medium",
    description:
      "The presented TLS certificate is close to expiry. Lapsed certificates cause browser trust warnings and open a window for downgrade and interception attacks.",
    remediation: "Automate certificate renewal (e.g. ACME / Let's Encrypt) and monitor expiry.",
    cvss: 5.3,
  },
  {
    title: "Server version disclosed in headers",
    category: "Information Disclosure",
    severity: "low",
    description:
      "The Server / X-Powered-By headers reveal the exact software and version, giving attackers a shortcut to version-specific exploits.",
    remediation: "Suppress or genericise server banner headers at the web server or proxy layer.",
    cvss: 3.1,
  },
  {
    title: "Forms submitted over unencrypted channel",
    category: "Transport",
    severity: "critical",
    description:
      "One or more forms post to a non-HTTPS endpoint. Credentials and personal data can be intercepted in transit.",
    remediation: "Force HTTPS site-wide with HSTS and redirect all form actions to TLS endpoints.",
    cvss: 9.1,
  },
  {
    title: "Reflected parameter without output encoding",
    category: "Injection",
    severity: "high",
    description:
      "A query parameter is reflected into the page without contextual output encoding, a classic indicator of cross-site scripting exposure.",
    remediation:
      "Apply context-aware output encoding and validate all user input server-side.",
    cvss: 7.4,
  },
  {
    title: "Directory listing enabled",
    category: "Misconfiguration",
    severity: "medium",
    description:
      "The server returns an index listing for directories without an index file, exposing internal file structure and potentially sensitive artifacts.",
    remediation: "Disable autoindex/directory listing and audit exposed paths.",
    cvss: 5.8,
  },
  {
    title: "Cookie missing Secure and HttpOnly flags",
    category: "Session Management",
    severity: "medium",
    description:
      "Session cookies are set without Secure and/or HttpOnly attributes, allowing theft via XSS or interception over plaintext channels.",
    remediation: "Set Secure, HttpOnly and SameSite=strict on all session cookies.",
    cvss: 6.1,
  },
  {
    title: "Outdated JavaScript library detected",
    category: "Dependencies",
    severity: "high",
    description:
      "A front-end library with known published CVEs is loaded. Known-vulnerable components are among the most exploited web weaknesses.",
    remediation: "Upgrade the flagged library and add dependency scanning (npm audit / Snyk) to CI.",
    cvss: 8.2,
  },
  {
    title: "Clickjacking protection absent",
    category: "HTTP Headers",
    severity: "medium",
    description:
      "Neither X-Frame-Options nor a CSP frame-ancestors directive is present, allowing the page to be framed by a malicious site for UI-redress attacks.",
    remediation: "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
    cvss: 4.7,
  },
  {
    title: "Verbose error messages exposed",
    category: "Information Disclosure",
    severity: "medium",
    description:
      "Stack traces and framework error details are returned to the client, leaking internal paths, queries and configuration.",
    remediation: "Return generic error pages in production and log detail server-side only.",
    cvss: 5.5,
  },
  {
    title: "Rate limiting not detected on auth endpoints",
    category: "Access Control",
    severity: "high",
    description:
      "Repeated requests to login-like endpoints receive no throttling response, enabling credential stuffing and brute-force attacks.",
    remediation: "Apply IP and account-based rate limiting plus progressive delays and MFA.",
    cvss: 7.5,
  },
  {
    title: "Cross-origin policy overly permissive",
    category: "Access Control",
    severity: "medium",
    description:
      "Access-Control-Allow-Origin reflects arbitrary origins, permitting untrusted sites to read authenticated API responses.",
    remediation: "Restrict CORS to an explicit allow-list of trusted origins.",
    cvss: 6.4,
  },
];

const TOOL_SETS = {
  passive: ["Wappalyzer", "SecurityHeaders.com probe", "SSL Labs scan", "Shodan banner lookup"],
  active: ["OWASP ZAP", "Nmap NSE scripts", "Nikto", "Nuclei templates", "Burp Suite passive scan"],
  recommended: [
    "Burp Suite Professional",
    "OWASP ZAP (full active scan)",
    "Nmap with vuln scripts",
    "SQLMap (authorised testing only)",
    "Metasploit Framework",
    "Amass / Subfinder for asset discovery",
  ],
};

function verdictFor(rating: number): ThreatAssessment["verdict"] {
  if (rating >= 70) return "Vulnerable";
  if (rating >= 45) return "At Risk";
  if (rating >= 25) return "Guarded";
  return "Hardened";
}

function buildThreats(r: () => number, hasFinding: (cat: string, sev: Severity) => boolean): ThreatAssessment[] {
  const sqliBias = hasFinding("Injection", "high") ? 25 : 0;
  const xssBias = hasFinding("Injection", "high") ? 20 : 0;
  const bruteBias = hasFinding("Access Control", "high") ? 22 : 0;

  const mk = (
    id: string,
    name: string,
    short: string,
    base: number,
    detail: string,
    attackVectors: string[],
    toolsUsed: string[],
    recommendedTools: string[]
  ): ThreatAssessment => {
    const rating = Math.min(96, Math.max(6, Math.round(base + r() * 22 - 8)));
    return { id, name, short, rating, verdict: verdictFor(rating), detail, attackVectors, toolsUsed, recommendedTools };
  };

  return [
    mk(
      "sqli",
      "SQL Injection",
      "SQLi",
      38 + sqliBias,
      "Assessment of input handling on data-driven endpoints. Parameters were fingerprinted for improper sanitisation and database error leakage that precede union-, error- and blind-based injection.",
      ["Union-based extraction", "Boolean blind inference", "Time-delay blind probes", "Second-order injection"],
      ["OWASP ZAP parameter fuzzing", "Header & form reflection probes"],
      ["SQLMap (authorised only)", "Burp Suite Intruder", "Prepared-statement code audit"]
    ),
    mk(
      "xss",
      "Cross-Site Scripting",
      "XSS",
      40 + xssBias,
      "Evaluation of output encoding and CSP posture across reflected and stored contexts, including DOM sinks reachable from URL fragments and form fields.",
      ["Reflected XSS", "Stored XSS", "DOM-based XSS", "Mutation XSS via rich text"],
      ["Reflected parameter probing", "CSP evaluation"],
      ["Burp Suite active scan", "XSStrike", "DOMPurify sanitisation"]
    ),
    mk(
      "mitm",
      "Phishing & Man-in-the-Middle",
      "MITM",
      30,
      "Review of transport security: TLS version floor, HSTS, certificate hygiene and email-authentication records (SPF/DMARC) that determine spoofing and interception exposure.",
      ["TLS downgrade", "Rogue Wi-Fi interception", "Lookalike-domain phishing", "SSL stripping"],
      ["SSL Labs grade check", "DNS record inspection"],
      ["Wireshark traffic audit", "Bettercap (lab only)", "HSTS preload submission"]
    ),
    mk(
      "ddos",
      "Distributed Denial of Service",
      "DDoS",
      34,
      "Estimation of resilience against volumetric and application-layer floods, based on CDN presence, response caching headers and observed rate-limiting behaviour.",
      ["HTTP flood (L7)", "SYN flood (L4)", "Slowloris connection exhaustion", "DNS amplification"],
      ["Rate-limit probing", "CDN/WAF fingerprinting"],
      ["Cloudflare / WAF ruleset", "Load test with k6", "Rate limiting at edge"]
    ),
    mk(
      "brute",
      "Brute Force & Credential Attacks",
      "Brute Force",
      36 + bruteBias,
      "Measurement of authentication surface hardness: lockout policy, throttling, MFA indicators and credential-stuffing resistance on login and reset flows.",
      ["Credential stuffing", "Dictionary attack", "Password spraying", "Session token guessing"],
      ["Auth endpoint rate testing", "Cookie flag inspection"],
      ["Hydra (authorised only)", "MFA enforcement", "Have I Been Pwned k-anonymity check"]
    ),
  ];
}

// ---------- public API ----------
export function runScan(rawUrl: string, mode: "quick" | "deep"): ScanReport {
  let url = rawUrl.trim();
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  const host = (() => {
    try {
      return new URL(url).hostname;
    } catch {
      return url.replace(/^https?:\/\//, "").split("/")[0];
    }
  })();

  const rand = mulberry32(hashString(host + "::" + mode));

  const findingCount = mode === "quick" ? 6 : 10;
  const pool = [...FINDING_POOL];
  const findings: Finding[] = [];
  for (let i = 0; i < findingCount && pool.length; i++) {
    const idx = Math.floor(rand() * pool.length);
    const f = pool.splice(idx, 1)[0];
    findings.push({ ...f, id: `ET-${String(i + 1).padStart(3, "0")}` });
  }
  // sort by severity weight
  const w: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => w[a.severity] - w[b.severity]);

  const penalty = findings.reduce((acc, f) => acc + f.cvss * (mode === "quick" ? 1.4 : 1.15), 0);
  const score = Math.max(8, Math.min(97, Math.round(100 - penalty * (0.7 + rand() * 0.2))));
  const grade = score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";

  const hasFinding = (cat: string, sev: Severity) => findings.some((f) => f.category === cat && f.severity === sev);
  const threats = buildThreats(rand, hasFinding);

  const toolsUsed = [
    ...TOOL_SETS.passive,
    ...(mode === "deep" ? TOOL_SETS.active : [pick(rand, TOOL_SETS.active)]),
  ];

  return {
    url,
    host,
    scannedAt: new Date().toISOString(),
    mode,
    score,
    grade,
    findings,
    threats,
    toolsUsed,
    recommendedTools: TOOL_SETS.recommended,
  };
}

export const severityColor: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#6b7280",
};
