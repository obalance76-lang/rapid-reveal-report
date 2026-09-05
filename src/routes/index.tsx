import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useRef, useState } from "react";
import { runScan, severityColor, type ScanReport, type ThreatAssessment } from "@/lib/analysis";
import { downloadIntroPdf, downloadThreatPdf } from "@/lib/pdf";
import logo from "@/assets/evaltech-logo.png";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Evaltech — Ethical Hacking Security Reports" },
      {
        name: "description",
        content:
          "Submit a site link and Evaltech runs a fast vulnerability check with a security score, findings and professional downloadable PDF reports.",
      },
    ],
  }),
  component: Index,
});

const QUICK_STEPS = [
  "Resolving host & fingerprinting stack…",
  "Probing TLS configuration…",
  "Inspecting HTTP security headers…",
  "Checking cookies & session flags…",
  "Correlating known weaknesses…",
];

const DEEP_STEPS = [
  ...QUICK_STEPS,
  "Enumerating endpoints & parameters…",
  "Fuzzing input surfaces (passive)…",
  "Testing auth throttling behaviour…",
  "Modelling threat exposure…",
  "Compiling findings & ratings…",
];

function scoreTone(score: number) {
  if (score >= 70) return "text-emerald-600";
  if (score >= 45) return "text-primary";
  return "text-red-600";
}

function verdictPill(v: ThreatAssessment["verdict"]) {
  switch (v) {
    case "Vulnerable":
      return "bg-red-100 text-red-700 border-red-200";
    case "At Risk":
      return "bg-orange-100 text-orange-700 border-orange-200";
    case "Guarded":
      return "bg-amber-100 text-amber-700 border-amber-200";
    case "Hardened":
      return "bg-emerald-100 text-emerald-700 border-emerald-200";
  }
}

function Index() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [phase, setPhase] = useState<"idle" | "scanning" | "done">("idle");
  const [stepIdx, setStepIdx] = useState(0);
  const [steps, setSteps] = useState<string[]>(QUICK_STEPS);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);
  const reportRef = useRef<HTMLDivElement>(null);

  const valid = useMemo(() => url.trim().length > 3 && url.trim().includes("."), [url]);

  const startScan = (mode: "quick" | "deep") => {
    if (!valid) {
      setError("Enter a valid site link, e.g. example.com");
      return;
    }
    setError("");
    setPhase("scanning");
    setReport(null);
    const seq = mode === "quick" ? QUICK_STEPS : DEEP_STEPS;
    setSteps(seq);
    setStepIdx(0);
    const per = mode === "quick" ? 520 : 620;
    seq.forEach((_, i) => setTimeout(() => setStepIdx(i), i * per));
    setTimeout(
      () => {
        setReport(runScan(url, mode));
        setPhase("done");
        setTimeout(() => reportRef.current?.scrollIntoView({ behavior: "smooth" }), 80);
      },
      seq.length * per + 300
    );
  };

  const handleDownload = async (key: string, fn: () => Promise<void>) => {
    setDownloading(key);
    try {
      await fn();
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* top bar */}
      <header className="border-b-2 border-foreground bg-background">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <img src={logo} alt="Evaltech logo" className="h-9 w-auto" width={1024} height={512} />
          <span className="hidden text-xs font-semibold uppercase tracking-[0.25em] text-muted-foreground sm:block">
            Ethical Hacking Documentation
          </span>
        </div>
      </header>

      {/* hero */}
      <section className="border-b border-border bg-accent text-accent-foreground">
        <div className="mx-auto max-w-5xl px-6 py-16 sm:py-20">
          <p className="mb-4 inline-block border border-primary px-3 py-1 text-[11px] font-bold uppercase tracking-[0.3em] text-primary">
            Security process · documented
          </p>
          <h1 className="max-w-2xl text-4xl font-black leading-[1.05] tracking-tight sm:text-6xl">
            How vulnerable is a site? <span className="text-primary">Find out fast.</span>
          </h1>
          <p className="mt-5 max-w-xl text-base text-accent-foreground/70 sm:text-lg">
            Submit a site link. Evaltech runs an initial vulnerability check, scores the site's
            security posture, and produces professional PDF assessment reports — instantly.
          </p>

          {/* input */}
          <div className="mt-10 flex max-w-2xl flex-col gap-3 sm:flex-row">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && startScan("quick")}
              placeholder="https://your-site.com"
              className="h-13 flex-1 border-2 border-accent-foreground/30 bg-transparent px-4 py-3 text-lg font-medium text-accent-foreground placeholder:text-accent-foreground/40 focus:border-primary focus:outline-none"
            />
            <div className="flex gap-3">
              <button
                onClick={() => startScan("quick")}
                disabled={phase === "scanning"}
                className="bg-primary px-6 py-3 text-sm font-bold uppercase tracking-widest text-primary-foreground transition hover:brightness-110 disabled:opacity-50"
              >
                Quick Analyze
              </button>
              <button
                onClick={() => startScan("deep")}
                disabled={phase === "scanning"}
                className="border-2 border-accent-foreground/40 px-6 py-3 text-sm font-bold uppercase tracking-widest transition hover:border-primary hover:text-primary disabled:opacity-50"
              >
                Long Analyze
              </button>
            </div>
          </div>
          {error && <p className="mt-3 text-sm font-semibold text-primary">{error}</p>}
          <p className="mt-4 text-xs text-accent-foreground/50">
            Initial checks are passive and non-intrusive. Only scan systems you are authorised to test.
          </p>
        </div>
      </section>

      {/* scanning */}
      {phase === "scanning" && (
        <section className="mx-auto max-w-5xl px-6 py-14">
          <div className="border border-border bg-card p-8">
            <div className="flex items-center gap-3">
              <span className="h-3 w-3 animate-ping rounded-full bg-primary" />
              <h2 className="text-xl font-bold">
                {steps.length > 5 ? "Deep analysis" : "Quick analysis"} in progress
              </h2>
            </div>
            <ul className="mt-6 space-y-2.5 font-mono text-sm">
              {steps.map((s, i) => (
                <li
                  key={s}
                  className={
                    i < stepIdx
                      ? "text-emerald-600"
                      : i === stepIdx
                        ? "text-foreground"
                        : "text-muted-foreground/40"
                  }
                >
                  {i < stepIdx ? "✓" : i === stepIdx ? "▸" : "·"} {s}
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}

      {/* report */}
      {phase === "done" && report && (
        <div ref={reportRef}>
          {/* score + intro pdf */}
          <section className="mx-auto max-w-5xl px-6 py-14">
            <div className="grid gap-6 md:grid-cols-[1fr_320px]">
              <div className="border border-border bg-card p-8">
                <p className="text-xs font-bold uppercase tracking-[0.25em] text-muted-foreground">
                  Security posture · {report.host}
                </p>
                <div className="mt-6 flex flex-wrap items-end gap-8">
                  <div>
                    <span className={`text-7xl font-black tabular-nums ${scoreTone(report.score)}`}>
                      {report.score}
                    </span>
                    <span className="text-2xl font-bold text-muted-foreground">/100</span>
                  </div>
                  <div className="pb-2">
                    <div
                      className={`inline-block border-2 px-4 py-1 text-2xl font-black ${scoreTone(report.score)} border-current`}
                    >
                      Grade {report.grade}
                    </div>
                    <p className="mt-2 text-sm text-muted-foreground">
                      {report.mode === "quick" ? "Quick initial check" : "Deep analysis"} ·{" "}
                      {report.findings.length} findings ·{" "}
                      {new Date(report.scannedAt).toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="mt-6 h-2.5 w-full bg-muted">
                  <div
                    className={`h-full ${report.score >= 70 ? "bg-emerald-500" : report.score >= 45 ? "bg-primary" : "bg-red-600"}`}
                    style={{ width: `${report.score}%` }}
                  />
                </div>
              </div>

              {/* intro PDF card */}
              <div className="flex flex-col justify-between border-2 border-primary bg-card p-8">
                <div>
                  <p className="text-xs font-bold uppercase tracking-[0.25em] text-primary">
                    Downloadable report
                  </p>
                  <h3 className="mt-2 text-xl font-black leading-tight">
                    Introductory Security Report
                  </h3>
                  <p className="mt-2 text-sm text-muted-foreground">
                    Full posture score, every finding with remediation, threat snapshot and tooling —
                    professionally formatted.
                  </p>
                </div>
                <button
                  onClick={() => handleDownload("intro", () => downloadIntroPdf(report))}
                  disabled={downloading !== null}
                  className="mt-6 w-full bg-accent px-4 py-3 text-sm font-bold uppercase tracking-widest text-accent-foreground transition hover:bg-primary hover:text-primary-foreground disabled:opacity-50"
                >
                  {downloading === "intro" ? "Building PDF…" : "⬇ Download PDF"}
                </button>
              </div>
            </div>
          </section>

          {/* findings */}
          <section className="mx-auto max-w-5xl px-6 pb-14">
            <h2 className="mb-6 flex items-center gap-3 text-2xl font-black">
              <span className="h-6 w-1.5 bg-primary" /> Findings
            </h2>
            <div className="overflow-hidden border border-border bg-card">
              {report.findings.map((f, i) => (
                <details key={f.id} className={i > 0 ? "border-t border-border" : ""}>
                  <summary className="flex cursor-pointer list-none items-center gap-4 px-5 py-4 hover:bg-muted/50">
                    <span
                      className="w-20 shrink-0 px-2 py-0.5 text-center text-[10px] font-bold uppercase text-white"
                      style={{ backgroundColor: severityColor[f.severity] }}
                    >
                      {f.severity}
                    </span>
                    <span className="flex-1 text-sm font-semibold">{f.title}</span>
                    <span className="hidden font-mono text-xs text-muted-foreground sm:block">
                      {f.id} · CVSS {f.cvss.toFixed(1)}
                    </span>
                  </summary>
                  <div className="border-t border-border bg-muted/30 px-5 py-4">
                    <p className="text-sm text-foreground/80">{f.description}</p>
                    <p className="mt-2 text-sm font-semibold text-primary">
                      Remediation: <span className="font-normal text-foreground/70">{f.remediation}</span>
                    </p>
                  </div>
                </details>
              ))}
            </div>
          </section>

          {/* 5 threat PDFs */}
          <section className="border-t-2 border-foreground bg-secondary">
            <div className="mx-auto max-w-5xl px-6 py-14">
              <h2 className="flex items-center gap-3 text-2xl font-black">
                <span className="h-6 w-1.5 bg-primary" /> Threat Assessments
              </h2>
              <p className="mt-2 max-w-xl text-sm text-muted-foreground">
                Five focused assessments — each a quick check of how vulnerable {report.host} is to a
                specific cyber-attack class, each with its own downloadable PDF.
              </p>
              <div className="mt-8 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
                {report.threats.map((t) => (
                  <div key={t.id} className="flex flex-col border border-border bg-card p-6">
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="text-lg font-black leading-tight">{t.name}</h3>
                      <span
                        className={`shrink-0 border px-2 py-0.5 text-[10px] font-bold uppercase ${verdictPill(t.verdict)}`}
                      >
                        {t.verdict}
                      </span>
                    </div>
                    <div className="mt-4 flex items-center gap-3">
                      <div className="h-2 flex-1 bg-muted">
                        <div
                          className={`h-full ${t.rating >= 70 ? "bg-red-600" : t.rating >= 45 ? "bg-primary" : t.rating >= 25 ? "bg-amber-500" : "bg-emerald-500"}`}
                          style={{ width: `${t.rating}%` }}
                        />
                      </div>
                      <span className="font-mono text-sm font-bold">{t.rating}%</span>
                    </div>
                    <p className="mt-3 flex-1 text-xs leading-relaxed text-muted-foreground">
                      {t.detail}
                    </p>
                    <button
                      onClick={() => handleDownload(t.id, () => downloadThreatPdf(report, t))}
                      disabled={downloading !== null}
                      className="mt-5 w-full border-2 border-accent px-4 py-2.5 text-xs font-bold uppercase tracking-widest text-accent transition hover:bg-primary hover:border-primary hover:text-primary-foreground disabled:opacity-50"
                    >
                      {downloading === t.id ? "Building PDF…" : `⬇ ${t.short} PDF`}
                    </button>
                  </div>
                ))}

                {/* process card */}
                <div className="flex flex-col justify-between border border-border bg-accent p-6 text-accent-foreground">
                  <div>
                    <h3 className="text-lg font-black">The Evaltech process</h3>
                    <ol className="mt-3 space-y-1.5 text-xs text-accent-foreground/70">
                      <li>1 · Reconnaissance</li>
                      <li>2 · Scanning & enumeration</li>
                      <li>3 · Vulnerability analysis</li>
                      <li>4 · Controlled validation</li>
                      <li>5 · Reporting & documentation</li>
                    </ol>
                  </div>
                  <p className="mt-4 text-[11px] text-accent-foreground/50">
                    Every report documents tools used and tools recommended for deeper authorised
                    testing.
                  </p>
                </div>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* footer */}
      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-5xl flex-col items-center justify-between gap-3 px-6 py-8 sm:flex-row">
          <img src={logo} alt="Evaltech" className="h-7 w-auto" width={1024} height={512} loading="lazy" />
          <p className="text-xs text-muted-foreground">
            Evaltech · Ethical hacking, documented. Only test systems you are authorised to assess.
          </p>
        </div>
      </footer>
    </div>
  );
}
