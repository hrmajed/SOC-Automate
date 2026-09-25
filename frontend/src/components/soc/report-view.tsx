"use client";

import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Check,
  Cloud,
  Database,
  EyeOff,
  Fingerprint,
  Laptop,
  Lock,
  ShieldAlert,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { PathNode, Report } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Pill, SEVERITY_STYLE, SOURCE, SourceIcon, VERDICT, hhmm } from "./format";
import { RichText } from "./rich-text";

const NODE_ICON: Record<PathNode["kind"], LucideIcon> = { host: Laptop, identity: Fingerprint, cloud: Cloud, data: Database };

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border bg-muted/20 px-3 py-2">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className="text-sm font-semibold tabular-nums">{value}</div>
    </div>
  );
}

export function VerdictBanner({ report }: { report: Report }) {
  const v = VERDICT[report.verdict];
  const blocked = report.guardrails.findings.filter((f) => f.layer !== "output" || f.kind !== "unsupported_technique").length;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Pill className={cn("h-6 px-2.5 text-xs", v.style)}>{v.label}</Pill>
        <Pill className={cn("h-6 px-2.5 text-xs", SEVERITY_STYLE[report.severity])}>Severity {report.severity}</Pill>
        <Pill className="h-6 border-border px-2.5 text-xs text-muted-foreground">Confidence {report.confidence}</Pill>
        {!report.guardrails.enabled && (
          <Pill className="h-6 border-red-500/50 bg-red-500/15 px-2.5 text-xs text-red-300">
            <AlertTriangle className="size-3" /> Guardrails disabled
          </Pill>
        )}
        <span className="ml-auto text-[11px] text-muted-foreground">
          Narrative: {report.narrative_source} · LLM: {report.llm.backend}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <Stat label="Tool calls" value={report.metrics.tool_calls} />
        <Stat label="Events reviewed" value={report.metrics.events_reviewed} />
        <Stat label="Log sources" value={report.metrics.sources.map((s) => SOURCE[s]?.label ?? s).join(" · ")} />
        <Stat label="ATT&CK techniques" value={report.attack_mapping.length} />
        <Stat label="PII values masked" value={report.pii.unique_values_masked} />
        <Stat label="Guardrail findings" value={<span className={blocked ? "text-amber-300" : ""}>{blocked}</span>} />
      </div>
    </div>
  );
}

export function AttackPath({ path, onOpen }: { path: PathNode[]; onOpen: (id: string) => void }) {
  if (!path.length) return null;
  return (
    <div className="flex flex-col gap-2 lg:flex-row lg:items-stretch">
      {path.map((n, i) => {
        const Icon = NODE_ICON[n.kind];
        return (
          <div key={n.id} className="flex flex-col items-stretch gap-2 lg:flex-1 lg:flex-row lg:items-center">
            <button
              onClick={() => onOpen(n.evidence_ids[0])}
              className="flex-1 rounded-lg border border-red-500/25 bg-red-500/[0.06] p-2.5 text-left transition-colors hover:bg-red-500/10"
            >
              <div className="flex items-center gap-1.5 text-[13px] font-semibold">
                <Icon className="size-3.5 text-red-300" />
                <span className="truncate">{n.label}</span>
              </div>
              <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{n.principals.join(", ") || n.detail}</div>
              <div className="mt-1 flex items-center justify-between text-[10.5px] text-muted-foreground">
                <span className="font-mono">{hhmm(n.first_seen).slice(0, 5)} UTC</span>
                <span>{n.techniques.length} TTPs</span>
              </div>
            </button>
            {i < path.length - 1 && <ArrowRight className="size-4 shrink-0 rotate-90 self-center text-red-300/70 lg:rotate-0" />}
          </div>
        );
      })}
    </div>
  );
}

function Narrative({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const [approved, setApproved] = useState<Record<string, boolean>>({});
  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
      <div className="space-y-3 text-[13.5px] leading-relaxed text-foreground/90">
        {report.narrative.split("\n\n").map((p, i) => (
          <p key={i}>
            <RichText text={p} report={report} onOpen={onOpen} />
          </p>
        ))}
      </div>
      <div>
        <h4 className="mb-2 flex items-center gap-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
          <Lock className="size-3.5" /> Recommended actions (human approval)
        </h4>
        <ul className="space-y-2">
          {report.recommended_actions.map((a) => (
            <li key={a.id} className="rounded-lg border bg-muted/20 p-2.5">
              <div className="flex items-start gap-2">
                <Pill className={a.priority === "P1" ? "border-red-500/40 text-red-300" : "border-border text-muted-foreground"}>
                  {a.priority}
                </Pill>
                <p className="flex-1 text-[12.5px] leading-snug">
                  <RichText text={a.action} report={report} onOpen={onOpen} />
                </p>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <span className="line-clamp-1 flex-1 text-[11px] text-muted-foreground">{a.rationale}</span>
                <Button
                  size="xs"
                  variant={approved[a.id] ? "secondary" : "outline"}
                  onClick={() => setApproved((s) => ({ ...s, [a.id]: !s[a.id] }))}
                >
                  {approved[a.id] ? (
                    <>
                      <Check /> Approved
                    </>
                  ) : (
                    "Approve"
                  )}
                </Button>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Timeline({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const [all, setAll] = useState(false);
  const rows = report.timeline.filter((t) => all || t.malicious);
  const hidden = report.timeline.length - report.timeline.filter((t) => t.malicious).length;
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-xs text-muted-foreground">
        <span>
          {rows.length} of {report.timeline.length} events · times in UTC
        </span>
        {hidden > 0 && (
          <Button size="xs" variant="ghost" onClick={() => setAll((v) => !v)}>
            {all ? "Hide context events" : `Show ${hidden} context events`}
          </Button>
        )}
      </div>
      <ol className="space-y-1">
        {rows.map((t) => (
          <li
            key={t.evidence_id}
            className={cn(
              "grid grid-cols-[64px_20px_1fr] items-start gap-2 rounded-md px-2 py-2 text-[12.5px] sm:grid-cols-[72px_20px_1fr_auto]",
              t.malicious ? "bg-muted/25" : "opacity-60",
              t.injection && "ring-1 ring-red-500/40",
            )}
          >
            <span className="font-mono text-[11.5px] text-muted-foreground">{hhmm(t.timestamp)}</span>
            <SourceIcon source={t.source} className="mt-0.5 size-3.5" />
            <div className="min-w-0">
              <p className="leading-snug">{t.summary}</p>
              <div className="mt-1 flex flex-wrap gap-1">
                {t.techniques.map((x) => (
                  <a key={x.id} href={x.url} target="_blank" rel="noreferrer">
                    <Pill
                      className={
                        x.id.startsWith("AML")
                          ? "border-red-500/40 bg-red-500/10 text-red-300"
                          : "border-primary/25 bg-primary/5 text-primary/90"
                      }
                    >
                      {x.id} {x.name.split(": ").pop()}
                    </Pill>
                  </a>
                ))}
                {t.notes.map((n) => (
                  <Pill key={n} className="border-amber-500/40 text-amber-200">
                    {n}
                  </Pill>
                ))}
              </div>
            </div>
            <button
              onClick={() => onOpen(t.evidence_id)}
              className="col-start-3 justify-self-start font-mono text-[11px] text-primary hover:underline sm:col-start-4"
            >
              {t.evidence_id}
            </button>
          </li>
        ))}
      </ol>
    </div>
  );
}

const TACTICS = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration",
];

function Attack({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const used = TACTICS.filter((t) => report.attack_mapping.some((m) => m.tactic === t));
  if (!used.length) return <p className="text-sm text-muted-foreground">No ATT&CK techniques mapped to malicious evidence.</p>;
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {used.map((tac) => (
        <div key={tac} className="rounded-lg border bg-muted/15 p-2">
          <h5 className="mb-2 px-1 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">{tac}</h5>
          <div className="space-y-1.5">
            {report.attack_mapping
              .filter((m) => m.tactic === tac)
              .map((m) => (
                <div
                  key={m.id}
                  className={cn(
                    "rounded-md border p-2",
                    m.id.startsWith("AML") ? "border-red-500/40 bg-red-500/10" : "border-primary/20 bg-primary/5",
                  )}
                >
                  <a href={m.url} target="_blank" rel="noreferrer" className="font-mono text-[11px] text-primary hover:underline">
                    {m.id}
                  </a>
                  <p className="text-[12px] leading-snug">{m.name}</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {m.evidence_ids?.slice(0, 4).map((e) => (
                      <button key={e} onClick={() => onOpen(e)} className="font-mono text-[10px] text-muted-foreground hover:text-primary">
                        {e}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function WhyHere({ report }: { report: Report }) {
  const KIND: Record<string, string> = {
    compliance: "Compliance", policy: "Policy", incident: "Past incident", asset: "Network map", cloud_asset: "Cloud inventory",
  };
  if (!report.environment_context.length)
    return <p className="text-sm text-muted-foreground">No environment-specific context was retrieved.</p>;
  return (
    <ul className="grid gap-2 md:grid-cols-2">
      {report.environment_context.map((e, i) => (
        <li key={i} className="rounded-lg border bg-muted/15 p-3">
          <div className="mb-1 flex flex-wrap items-center gap-1.5">
            <Pill className="border-violet-400/30 bg-violet-400/10 text-violet-200">{KIND[e.kind] ?? e.kind}</Pill>
            {e.doc_id && <span className="font-mono text-[11px] text-muted-foreground">{e.doc_id}</span>}
            <Pill className="ml-auto border-emerald-500/30 text-emerald-300">
              <ShieldCheck className="size-3" /> {e.trust}
            </Pill>
          </div>
          <p className="text-[13px] leading-snug">{e.statement}</p>
          <p className="mt-1 text-[11px] text-muted-foreground">
            {e.title} · {e.relevance}
          </p>
        </li>
      ))}
    </ul>
  );
}

function Guardrails({ report }: { report: Report }) {
  const g = report.guardrails;
  const LAYER: Record<string, string> = { input: "Input guard", rag: "RAG guard", tool: "Tool policy", output: "Output guard" };
  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-3">
        <div className="rounded-lg border bg-muted/15 p-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <EyeOff className="size-4 text-primary" /> PII masked before the LLM
          </div>
          <p className="mt-1 text-[12px] text-muted-foreground">
            {report.pii.unique_values_masked} unique values · {report.pii.replacements} replacements
          </p>
          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(report.pii.by_type).map(([k, v]) => (
              <Pill key={k} className="border-border text-muted-foreground">
                {k} × {v}
              </Pill>
            ))}
          </div>
        </div>
        <div className="rounded-lg border bg-muted/15 p-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <ShieldCheck className="size-4 text-primary" /> Spotlighting
          </div>
          <p className="mt-1 text-[12px] text-muted-foreground">
            {g.spotlight_nonce ? (
              <>
                Untrusted data wrapped in nonce-tagged blocks <span className="font-mono text-foreground">{g.spotlight_nonce}</span>
              </>
            ) : (
              "Disabled"
            )}
          </p>
        </div>
        <div className="rounded-lg border bg-muted/15 p-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <BookOpen className="size-4 text-primary" /> Knowledge-base quarantine
          </div>
          {g.kb_quarantine.map((q) => (
            <p key={q.doc_id} className="mt-1 text-[12px] text-muted-foreground">
              <span className="font-mono text-foreground">{q.doc_id}</span> ({q.source}): {q.reason}
            </p>
          ))}
        </div>
      </div>
      {report.executed_forbidden.length > 0 && (
        <div className="rounded-lg border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">
          <AlertTriangle className="mr-1 inline size-4" /> With guardrails off the agent executed:{" "}
          {report.executed_forbidden.map((t) => t.tool).join(", ")}
        </div>
      )}
      <div>
        <h4 className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">Findings</h4>
        {g.findings.length === 0 && g.rag_blocked.length === 0 ? (
          <p className="text-sm text-muted-foreground">No guardrail findings for this investigation.</p>
        ) : (
          <ul className="space-y-1.5">
            {g.findings.map((f) => (
              <li key={f.id} className="rounded-lg border bg-muted/15 p-2.5 text-[12.5px]">
                <div className="flex flex-wrap items-center gap-2">
                  <ShieldAlert className={cn("size-3.5", f.severity === "high" ? "text-red-300" : "text-amber-300")} />
                  <span className="font-medium">{f.kind.replace(/_/g, " ")}</span>
                  <Pill className="border-border text-muted-foreground">{LAYER[f.layer]}</Pill>
                  <span className="font-mono text-[11px] text-muted-foreground">{f.location}</span>
                  <span className="ml-auto text-[11px] text-primary">{f.action}</span>
                </div>
                <p className="mt-1 text-muted-foreground">{f.detail}</p>
                {f.snippet && (
                  <p className="mt-1 rounded bg-black/30 px-2 py-1 font-mono text-[11px] text-red-200/90">“{f.snippet}”</p>
                )}
              </li>
            ))}
            {g.rag_blocked.map((b) => (
              <li key={b.doc_id} className="rounded-lg border bg-muted/15 p-2.5 text-[12.5px]">
                <div className="flex flex-wrap items-center gap-2">
                  <ShieldAlert className="size-3.5 text-amber-300" />
                  <span className="font-medium">retrieval blocked</span>
                  <Pill className="border-border text-muted-foreground">RAG guard</Pill>
                  <span className="font-mono text-[11px] text-muted-foreground">{b.doc_id}</span>
                  <span className="ml-auto text-[11px] text-primary">excluded from context</span>
                </div>
                <p className="mt-1 text-muted-foreground">
                  {b.title}: {b.reason}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function LlmView({ report }: { report: Report }) {
  return (
    <div className="space-y-2">
      <p className="text-[12px] text-muted-foreground">
        The exact conversation the model saw ({report.llm.backend} · {report.llm.model}, {report.llm.rounds} rounds). Identities
        and secrets are pseudonymised, and log content sits inside untrusted-data blocks.
      </p>
      <div className="max-h-[520px] space-y-2 overflow-y-auto">
        {report.llm.transcript.map((m, i) => (
          <details key={i} className="rounded-lg border bg-muted/15" open={i < 2}>
            <summary className="cursor-pointer px-3 py-1.5 text-[12px]">
              <span className="font-mono font-medium">{m.role}</span>
              {m.tool_name && <span className="ml-2 font-mono text-muted-foreground">{m.tool_name}</span>}
              {m.tool_calls && (
                <span className="ml-2 text-muted-foreground">
                  → {(m.tool_calls as { function: { name: string } }[]).map((c) => c.function.name).join(", ")}
                </span>
              )}
            </summary>
            <pre className="max-h-72 overflow-auto border-t px-3 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-muted-foreground">
              {m.content || JSON.stringify(m.tool_calls, null, 1)}
            </pre>
          </details>
        ))}
      </div>
    </div>
  );
}

export function ReportTabs({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const findings = report.guardrails.findings.length + report.guardrails.rag_blocked.length;
  return (
    <Tabs defaultValue="story" className="gap-4">
      <TabsList className="h-auto flex-wrap">
        <TabsTrigger value="story">Attack story</TabsTrigger>
        <TabsTrigger value="timeline">Timeline</TabsTrigger>
        <TabsTrigger value="attack">MITRE ATT&CK</TabsTrigger>
        <TabsTrigger value="why">Why it matters here</TabsTrigger>
        <TabsTrigger value="guardrails">
          Guardrails {findings > 0 && <span className="ml-1 rounded-full bg-amber-500/20 px-1.5 text-[10px] text-amber-200">{findings}</span>}
        </TabsTrigger>
        <TabsTrigger value="llm">LLM view</TabsTrigger>
      </TabsList>
      <TabsContent value="story">
        <Narrative report={report} onOpen={onOpen} />
      </TabsContent>
      <TabsContent value="timeline">
        <Timeline report={report} onOpen={onOpen} />
      </TabsContent>
      <TabsContent value="attack">
        <Attack report={report} onOpen={onOpen} />
      </TabsContent>
      <TabsContent value="why">
        <WhyHere report={report} />
      </TabsContent>
      <TabsContent value="guardrails">
        <Guardrails report={report} />
      </TabsContent>
      <TabsContent value="llm">
        <LlmView report={report} />
      </TabsContent>
    </Tabs>
  );
}
