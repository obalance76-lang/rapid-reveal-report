import { jsPDF } from "jspdf";
import type { ScanReport, ThreatAssessment, Finding, Severity } from "./analysis";
import logoUrl from "@/assets/evaltech-logo.png";

// ---------- brand ----------
const ORANGE: [number, number, number] = [234, 88, 12];
const BLACK: [number, number, number] = [17, 17, 17];
const GRAY: [number, number, number] = [110, 110, 110];
const LIGHT: [number, number, number] = [245, 245, 245];

const SEV_RGB: Record<Severity, [number, number, number]> = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [217, 119, 6],
  low: [37, 99, 235],
  info: [107, 114, 128],
};

const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN = 20;
const CONTENT_W = PAGE_W - MARGIN * 2;

let logoData: string | null = null;
async function loadLogo(): Promise<string | null> {
  if (logoData) return logoData;
  try {
    const res = await fetch(logoUrl);
    const blob = await res.blob();
    logoData = await new Promise<string>((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result as string);
      fr.onerror = reject;
      fr.readAsDataURL(blob);
    });
    return logoData;
  } catch {
    return null;
  }
}

function header(doc: jsPDF, logo: string | null, title: string, subtitle: string) {
  // top band
  doc.setFillColor(...BLACK);
  doc.rect(0, 0, PAGE_W, 34, "F");
  doc.setFillColor(...ORANGE);
  doc.rect(0, 34, PAGE_W, 1.6, "F");

  if (logo) {
    doc.addImage(logo, "PNG", MARGIN, 7, 40, 20);
  } else {
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("EVALTECH", MARGIN, 20);
  }
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text(title, PAGE_W - MARGIN, 15, { align: "right" });
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(200, 200, 200);
  doc.text(subtitle, PAGE_W - MARGIN, 22, { align: "right" });
}

function footer(doc: jsPDF, page: number) {
  doc.setFontSize(7.5);
  doc.setTextColor(...GRAY);
  doc.setFont("helvetica", "normal");
  doc.text(
    "Evaltech Security Assessment — Confidential — For authorised testing only",
    MARGIN,
    PAGE_H - 10
  );
  doc.text(`Page ${page}`, PAGE_W - MARGIN, PAGE_H - 10, { align: "right" });
  doc.setDrawColor(...ORANGE);
  doc.setLineWidth(0.4);
  doc.line(MARGIN, PAGE_H - 14, PAGE_W - MARGIN, PAGE_H - 14);
}

function sectionTitle(doc: jsPDF, text: string, y: number): number {
  doc.setFillColor(...ORANGE);
  doc.rect(MARGIN, y, 3, 7, "F");
  doc.setTextColor(...BLACK);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12.5);
  doc.text(text, MARGIN + 6, y + 5.4);
  return y + 12;
}

function bodyText(doc: jsPDF, text: string, y: number, size = 9.5): number {
  doc.setTextColor(60, 60, 60);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(size);
  const lines = doc.splitTextToSize(text, CONTENT_W);
  doc.text(lines, MARGIN, y);
  return y + lines.length * (size * 0.45);
}

function scoreGauge(doc: jsPDF, cx: number, cy: number, r: number, score: number, grade: string) {
  // background ring
  doc.setDrawColor(230, 230, 230);
  doc.setLineWidth(6);
  doc.circle(cx, cy, r, "S");
  // arc approximation: many small line segments
  const segs = 60;
  const filled = Math.round((score / 100) * segs);
  const color: [number, number, number] =
    score >= 70 ? [22, 163, 74] : score >= 45 ? ORANGE : [220, 38, 38];
  doc.setDrawColor(...color);
  doc.setLineWidth(6);
  for (let i = 0; i < filled; i++) {
    const a1 = -Math.PI / 2 + (i / segs) * Math.PI * 2;
    const a2 = -Math.PI / 2 + ((i + 1) / segs) * Math.PI * 2;
    doc.line(
      cx + Math.cos(a1) * r,
      cy + Math.sin(a1) * r,
      cx + Math.cos(a2) * r,
      cy + Math.sin(a2) * r
    );
  }
  doc.setTextColor(...BLACK);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(26);
  doc.text(String(score), cx, cy + 1, { align: "center" });
  doc.setFontSize(9);
  doc.setTextColor(...GRAY);
  doc.text("/ 100", cx, cy + 8, { align: "center" });
  doc.setFontSize(14);
  doc.setTextColor(...color);
  doc.text(`Grade ${grade}`, cx, cy + r + 12, { align: "center" });
}

function barMeter(doc: jsPDF, x: number, y: number, w: number, pct: number, label: string) {
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(...BLACK);
  doc.text(label, x, y);
  doc.setFillColor(...LIGHT);
  doc.roundedRect(x, y + 1.6, w, 4.6, 2, 2, "F");
  const color: [number, number, number] =
    pct >= 70 ? [220, 38, 38] : pct >= 45 ? ORANGE : pct >= 25 ? [217, 119, 6] : [22, 163, 74];
  doc.setFillColor(...color);
  doc.roundedRect(x, y + 1.6, Math.max(3, (w * pct) / 100), 4.6, 2, 2, "F");
  doc.setFont("helvetica", "bold");
  doc.text(`${pct}%`, x + w, y, { align: "right" });
  return y + 11;
}

function severityChip(doc: jsPDF, sev: Severity, x: number, y: number): number {
  const [r, g, b] = SEV_RGB[sev];
  const label = sev.toUpperCase();
  doc.setFont("helvetica", "bold");
  doc.setFontSize(7);
  const w = doc.getTextWidth(label) + 5;
  doc.setFillColor(r, g, b);
  doc.roundedRect(x, y - 3.2, w, 5, 1.2, 1.2, "F");
  doc.setTextColor(255, 255, 255);
  doc.text(label, x + 2.5, y);
  return w;
}

const TEXT_X = MARGIN + 34;
const TEXT_W = CONTENT_W - 38;
const DESC_LH = 3.9; // mm per line at 8.3pt
const REM_LH = 3.7; // mm per line at 7.8pt

function findingsTable(doc: jsPDF, findings: Finding[], startY: number, onNewPage?: () => void): number {
  let y = startY;
  for (const f of findings) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.3);
    const descLines: string[] = doc.splitTextToSize(f.description, TEXT_W);
    doc.setFontSize(7.8);
    const remLines: string[] = doc.splitTextToSize(`Remediation: ${f.remediation}`, TEXT_W);

    const descTop = 15.5; // baseline of first description line, relative to card top
    const remTop = descTop + descLines.length * DESC_LH + 2.4;
    const blockH = remTop + (remLines.length - 1) * REM_LH + 5; // bottom padding

    if (y + blockH > PAGE_H - 24) {
      doc.addPage();
      onNewPage?.();
      y = MARGIN + 6;
    }

    doc.setDrawColor(225, 225, 225);
    doc.setFillColor(252, 252, 252);
    doc.roundedRect(MARGIN, y, CONTENT_W, blockH, 2, 2, "FD");

    severityChip(doc, f.severity, MARGIN + 3, y + 6.6);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(9.5);
    doc.setTextColor(...BLACK);
    doc.text(f.title, TEXT_X, y + 6.6);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(...GRAY);
    doc.text(`${f.id} · ${f.category} · CVSS ${f.cvss.toFixed(1)}`, TEXT_X, y + 10.9);

    doc.setFontSize(8.3);
    doc.setTextColor(70, 70, 70);
    descLines.forEach((ln, i) => doc.text(ln, TEXT_X, y + descTop + i * DESC_LH));

    doc.setFontSize(7.8);
    doc.setTextColor(...ORANGE);
    remLines.forEach((ln, i) => doc.text(ln, TEXT_X, y + remTop + i * REM_LH));

    y += blockH + 3.5;
  }
  return y;
}

function toolList(doc: jsPDF, title: string, tools: string[], y: number): number {
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9.5);
  doc.setTextColor(...BLACK);
  doc.text(title, MARGIN, y);
  y += 5;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.8);
  doc.setTextColor(70, 70, 70);
  for (const t of tools) {
    doc.setFillColor(...ORANGE);
    doc.circle(MARGIN + 1.4, y - 1.2, 0.9, "F");
    doc.text(t, MARGIN + 5, y);
    y += 5;
  }
  return y + 3;
}

function sanitizeFile(s: string) {
  return s.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase();
}

// ============================================================
// 1) INTRODUCTORY REPORT (initial quick check)
// ============================================================
export async function downloadIntroPdf(report: ScanReport) {
  const logo = await loadLogo();
  const doc = new jsPDF();
  let page = 1;

  header(doc, logo, "Security Posture Report", report.host);
  let y = 48;

  // meta block
  doc.setFillColor(...LIGHT);
  doc.roundedRect(MARGIN, y, CONTENT_W, 24, 2, 2, "F");
  doc.setFontSize(8.5);
  doc.setTextColor(...GRAY);
  doc.setFont("helvetica", "bold");
  doc.text("TARGET", MARGIN + 5, y + 7);
  doc.text("SCAN TYPE", MARGIN + 5, y + 14);
  doc.text("DATE (UTC)", MARGIN + 5, y + 21);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(...BLACK);
  doc.text(report.url, MARGIN + 38, y + 7);
  doc.text(report.mode === "quick" ? "Quick initial check" : "Deep analysis", MARGIN + 38, y + 14);
  doc.text(new Date(report.scannedAt).toUTCString(), MARGIN + 38, y + 21);
  y += 34;

  // score
  scoreGauge(doc, MARGIN + 30, y + 24, 18, report.score, report.grade);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.setTextColor(...BLACK);
  doc.text("Overall Security Score", MARGIN + 30, y - 3, { align: "center" });

  let ry = y + 2;
  ry = sectionTitle(doc, "Executive Summary", ry) - 6;
  doc.setFontSize(9.5);
  const counts = {
    critical: report.findings.filter((f) => f.severity === "critical").length,
    high: report.findings.filter((f) => f.severity === "high").length,
    medium: report.findings.filter((f) => f.severity === "medium").length,
    low: report.findings.filter((f) => f.severity === "low").length,
  };
  ry = bodyText(
    doc,
    `Evaltech performed a ${report.mode === "quick" ? "rapid, non-intrusive initial check" : "comprehensive deep analysis"} of ${report.host}. ` +
      `The site scores ${report.score}/100 (grade ${report.grade}). The scan surfaced ${report.findings.length} findings: ` +
      `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium and ${counts.low} low severity. ` +
      (report.score >= 70
        ? "The overall posture is sound, with targeted hardening recommended below."
        : report.score >= 45
          ? "The posture shows meaningful weaknesses that should be prioritised for remediation."
          : "The posture is weak; immediate remediation of critical and high findings is advised."),
    ry
  );
  y = Math.max(ry + 8, y + 56);

  y = sectionTitle(doc, "Findings Overview", y);
  findingsTable(doc, report.findings, y);

  doc.addPage();
  page++;
  y = MARGIN + 6;
  y = sectionTitle(doc, "Threat Exposure Snapshot", y);
  for (const t of report.threats) {
    if (y > PAGE_H - 40) {
      doc.addPage();
      page++;
      y = MARGIN + 6;
    }
    y = barMeter(doc, MARGIN + 2, y, CONTENT_W - 30, t.rating, `${t.name} — ${t.verdict}`);
  }
  y += 4;
  y = toolList(doc, "Tools used in this assessment", report.toolsUsed, y + 2);
  toolList(doc, "Recommended tools for deeper testing", report.recommendedTools, y);

  for (let p = 1; p <= page; p++) {
    doc.setPage(p);
    footer(doc, p);
  }
  doc.save(`evaltech-report-${sanitizeFile(report.host)}.pdf`);
}

// ============================================================
// 2) PER-THREAT ASSESSMENT PDF
// ============================================================
export async function downloadThreatPdf(report: ScanReport, threat: ThreatAssessment) {
  const logo = await loadLogo();
  const doc = new jsPDF();
  let page = 1;

  header(doc, logo, `${threat.name} Assessment`, report.host);
  let y = 48;

  doc.setFillColor(...LIGHT);
  doc.roundedRect(MARGIN, y, CONTENT_W, 24, 2, 2, "F");
  doc.setFontSize(8.5);
  doc.setTextColor(...GRAY);
  doc.setFont("helvetica", "bold");
  doc.text("TARGET", MARGIN + 5, y + 7);
  doc.text("THREAT CLASS", MARGIN + 5, y + 14);
  doc.text("DATE (UTC)", MARGIN + 5, y + 21);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(...BLACK);
  doc.text(report.url, MARGIN + 38, y + 7);
  doc.text(`${threat.name} (${threat.short})`, MARGIN + 38, y + 14);
  doc.text(new Date(report.scannedAt).toUTCString(), MARGIN + 38, y + 21);
  y += 36;

  // vulnerability rating
  y = sectionTitle(doc, "Vulnerability Rating", y);
  const color: [number, number, number] =
    threat.rating >= 70 ? [220, 38, 38] : threat.rating >= 45 ? ORANGE : threat.rating >= 25 ? [217, 119, 6] : [22, 163, 74];
  doc.setFont("helvetica", "bold");
  doc.setFontSize(30);
  doc.setTextColor(...color);
  doc.text(`${threat.rating}%`, MARGIN, y + 11);
  doc.setFontSize(11);
  doc.setTextColor(...BLACK);
  doc.text(threat.verdict, MARGIN + 30, y + 11);
  doc.setFillColor(...LIGHT);
  doc.roundedRect(MARGIN, y + 16, CONTENT_W, 5.5, 2.5, 2.5, "F");
  doc.setFillColor(...color);
  doc.roundedRect(MARGIN, y + 16, Math.max(4, (CONTENT_W * threat.rating) / 100), 5.5, 2.5, 2.5, "F");
  y += 28;

  y = sectionTitle(doc, "Assessment Detail", y);
  y = bodyText(doc, threat.detail, y);
  y += 6;

  y = sectionTitle(doc, "Relevant Findings", y);
  const related = report.findings.slice(0, 5);
  y = findingsTable(doc, related, y);
  y += 4;

  doc.addPage();
  page++;
  y = MARGIN + 6;

  y = sectionTitle(doc, "Known Attack Vectors", y);
  doc.setFontSize(9);
  doc.setTextColor(70, 70, 70);
  doc.setFont("helvetica", "normal");
  for (const v of threat.attackVectors) {
    doc.setFillColor(...ORANGE);
    doc.circle(MARGIN + 1.4, y - 1.2, 0.9, "F");
    doc.text(v, MARGIN + 5, y);
    y += 5.4;
  }
  y += 6;

  y = toolList(doc, "Tools used in this assessment", threat.toolsUsed, y);
  y = toolList(doc, "Recommended tools for deeper testing", threat.recommendedTools, y);

  y = sectionTitle(doc, "Ethical Hacking Process Reference", y + 2);
  const steps = [
    "1. Reconnaissance — passive and active information gathering against the target.",
    "2. Scanning & Enumeration — fingerprinting services, endpoints and technologies.",
    "3. Vulnerability Analysis — correlating discovered surfaces with known weaknesses.",
    "4. Exploitation (authorised, controlled) — validating impact with proof-of-concept only.",
    "5. Reporting — documenting findings, ratings and remediation guidance (this document).",
  ];
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.8);
  doc.setTextColor(70, 70, 70);
  for (const s of steps) {
    const lines = doc.splitTextToSize(s, CONTENT_W);
    doc.text(lines, MARGIN, y);
    y += lines.length * 4.4 + 1;
  }
  y += 4;
  doc.setFontSize(7.8);
  doc.setTextColor(...GRAY);
  doc.text(
    doc.splitTextToSize(
      "Disclaimer: This document is produced for defensive, authorised security evaluation. Always obtain written permission before testing any system you do not own.",
      CONTENT_W
    ),
    MARGIN,
    y
  );

  for (let p = 1; p <= page; p++) {
    doc.setPage(p);
    footer(doc, p);
  }
  doc.save(`evaltech-${threat.short.toLowerCase().replace(/\s+/g, "-")}-${sanitizeFile(report.host)}.pdf`);
}
