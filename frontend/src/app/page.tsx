"use client";

import { Bot, Cpu, FlaskConical, Radar, RotateCcw, ShieldCheck, ShieldOff, Sparkles, WifiOff } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Alert as AlertBox, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { AgentTrace } from "@/components/soc/agent-trace";
import { AlertQueue } from "@/components/soc/alert-queue";
import { EvalsPanel } from "@/components/soc/evals-panel";
import { EvidenceSheet } from "@/components/soc/evidence-sheet";
import { Pill, SeverityPill, SourceIcon, SOURCE, dayTime } from "@/components/soc/format";
import { AttackPath, ReportTabs, VerdictBanner } from "@/components/soc/report-view";
import { api, investigateStream, type Alert, type Health, type Report, type Step } from "@/lib/api";
import { cn } from "@/lib/utils";

type View = "triage" | "evals";

export default function Console() {
  const [view, setView] = useState<View>("triage");
  const [health, setHealth] = useState<Health | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [steps, setSteps] = useState<Step[]>([]);
  const [phase, setPhase] = useState("");
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [guardrails, setGuardrails] = useState(true);
  const [evidenceId, setEvidenceId] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const detailRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async () => {
    try {
      const [h, a] = await Promise.all([api.health(), api.alerts()]);
      setHealth(h);
      setAlerts(a);
      setApiError(null);
      setSelected((s) => s ?? a[0]?.id ?? null);
    } catch (e) {
      setApiError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const select = async (id: string) => {
    abort.current?.abort();
    setRunning(false);
    setSelected(id);
    setSteps([]);
    setRunError(null);
    setReport(await api.report(id).catch(() => null));
    if (window.innerWidth < 1024) detailRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const investigate = async () => {
    if (!selected) return;
    abort.current?.abort();
    const ctrl = new AbortController();
    abort.current = ctrl;
    setRunning(true);
    setReport(null);
    setSteps([]);
    setRunError(null);
    setPhase("Starting investigation");
    try {
      await investigateStream(
        selected,
        { guardrails, paceMs: health?.llm.backend === "mock" ? 140 : 0, signal: ctrl.signal },
        (ev) => {
          if (ev.type === "phase") setPhase(ev.message);
          else if (ev.type === "tool_call") setSteps((s) => [...s, ev]);
          else if (ev.type === "tool_result") setSteps((s) => s.map((x) => (x.step === ev.step ? ev : x)));
          else if (ev.type === "error" && ev.fatal) setRunError(ev.message);
          else if (ev.type === "report") setReport(ev.report);
        },
      );
      await refresh();
    } catch (e) {
      if (!ctrl.signal.aborted) setRunError(e instanceof Error ? e.message : String(e));
    } finally {
      if (abort.current === ctrl) setRunning(false);
    }
  };

  const alert = alerts.find((a) => a.id === selected) ?? null;
  const progress = running ? Math.min(95, 8 + steps.length * 3.2) : report ? 100 : 0;

  return (
    <div className="bg-grid min-h-screen">
      <header className="sticky top-0 z-20 border-b bg-background/85 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <div className="flex size-7 items-center justify-center rounded-md bg-primary/15 text-primary">
              <Radar className="size-4" />
            </div>
            <div className="leading-tight">
              <div className="text-sm font-semibold">SOC Copilot</div>
              <div className="text-[11px] text-muted-foreground">Helix Dynamics · Tier-1 triage</div>
            </div>
          </div>
          <nav className="flex gap-1 rounded-lg border bg-muted/30 p-0.5">
            {(
              [
                ["triage", "Alert triage", Sparkles],
                ["evals", "Guardrail evals", FlaskConical],
              ] as const
            ).map(([v, label, Icon]) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={cn(
                  "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[13px] transition-colors",
                  view === v ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="size-3.5" /> {label}
              </button>
            ))}
          </nav>
          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            {health && (
              <>
                <Pill className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
                  <WifiOff className="size-3" /> Offline · telemetry stays local
                </Pill>
                <Pill className="border-border text-muted-foreground">
                  <Cpu className="size-3" /> {health.llm.backend === "mock" ? "Mock LLM (deterministic)" : `Ollama · ${health.llm.model}`}
                </Pill>
                <Pill className="hidden border-border text-muted-foreground md:inline-flex">
                  RAG {health.knowledge.chunks} chunks · {health.knowledge.embedder}
                </Pill>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] p-4">
        {apiError && (
          <AlertBox variant="destructive" className="mb-4">
            <AlertTitle>Cannot reach the SOC Copilot API</AlertTitle>
            <AlertDescription>
              {apiError}. Start the backend with <code className="font-mono">./scripts/dev.sh</code> (or{" "}
              <code className="font-mono">uvicorn soc_copilot.api:app --port 8765</code>), then{" "}
              <button className="underline" onClick={refresh}>
                retry
              </button>
              .
            </AlertDescription>
          </AlertBox>
        )}

        {view === "evals" ? (
          <EvalsPanel />
        ) : (
          <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
            <Card className="gap-0 self-start py-0 lg:sticky lg:top-[68px]">
              <CardHeader className="border-b px-4 py-3">
                <CardTitle className="flex items-center justify-between text-sm">
                  Alert queue <span className="text-xs font-normal text-muted-foreground">{alerts.length} open</span>
                </CardTitle>
              </CardHeader>
              <div className="max-h-[40vh] overflow-y-auto lg:max-h-[calc(100vh-140px)]">
                <AlertQueue alerts={alerts} selected={selected} onSelect={select} loading={loading} />
              </div>
            </Card>

            <div ref={detailRef} className="min-w-0 space-y-4">
              {alert ? (
                <>
                  <Card className="gap-3">
                    <CardHeader className="gap-2">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <SourceIcon source={alert.source} className="size-3.5" />
                        {SOURCE[alert.source]?.label}
                        <span className="font-mono">{alert.id}</span>·<span className="font-mono">{alert.rule}</span>·
                        <span>{dayTime(alert.created_at)}</span>
                        <SeverityPill severity={alert.severity} />
                      </div>
                      <CardTitle className="text-lg">{alert.title}</CardTitle>
                      <p className="text-[13px] text-muted-foreground">{alert.description}</p>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-center">
                      <div className="flex flex-1 flex-wrap gap-1.5">
                        {[...alert.entities.hosts, ...alert.entities.users, ...alert.entities.ips].map((e) => (
                          <Pill key={e} className="border-border font-mono text-muted-foreground">
                            {e}
                          </Pill>
                        ))}
                      </div>
                      <label
                        className={cn(
                          "flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs",
                          guardrails ? "text-muted-foreground" : "border-red-500/50 bg-red-500/10 text-red-300",
                        )}
                      >
                        {guardrails ? <ShieldCheck className="size-3.5 text-primary" /> : <ShieldOff className="size-3.5" />}
                        Guardrails
                        <Switch checked={guardrails} onCheckedChange={setGuardrails} disabled={running} />
                      </label>
                      <Button onClick={investigate} disabled={running} size="lg" className="px-4">
                        {report && !running ? <RotateCcw /> : <Bot />}
                        {running ? "Investigating…" : report ? "Re-investigate" : "Investigate with AI"}
                      </Button>
                    </CardContent>
                  </Card>

                  {runError && (
                    <AlertBox variant="destructive">
                      <AlertTitle>Investigation failed</AlertTitle>
                      <AlertDescription>{runError}</AlertDescription>
                    </AlertBox>
                  )}

                  {(running || steps.length > 0) && (
                    <Card className="gap-3">
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-sm">
                          <Bot className="size-4 text-primary" /> Agent trace
                          <span className="font-normal text-muted-foreground">
                            · {steps.length} tool calls{report ? ` · ${report.metrics.events_reviewed} events · ${(report.metrics.duration_ms / 1000).toFixed(1)} s end-to-end` : ""}
                          </span>
                        </CardTitle>
                        <Progress value={progress} className="h-1" />
                      </CardHeader>
                      <CardContent>
                        <AgentTrace steps={steps} running={running} phase={phase} />
                      </CardContent>
                    </Card>
                  )}

                  {report && (
                    <>
                      <Card className="gap-4">
                        <CardContent className="space-y-4">
                          <VerdictBanner report={report} />
                          {report.attack_path.length > 0 && (
                            <div>
                              <h4 className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                                Reconstructed attack path
                              </h4>
                              <AttackPath path={report.attack_path} onOpen={setEvidenceId} />
                            </div>
                          )}
                        </CardContent>
                      </Card>
                      <Card>
                        <CardContent>
                          <ReportTabs report={report} onOpen={setEvidenceId} />
                        </CardContent>
                      </Card>
                    </>
                  )}

                  {!running && !report && steps.length === 0 && !runError && (
                    <div className="rounded-xl border border-dashed p-8 text-center">
                      <Bot className="mx-auto mb-3 size-8 text-primary/70" />
                      <h3 className="font-medium">Let the agent do the first hour of this ticket</h3>
                      <p className="mx-auto mt-1 max-w-xl text-sm text-muted-foreground">
                        The agent masks personal data, pivots across EDR, CloudTrail and Okta with read-only tools, retrieves your
                        network map, past incidents and compliance obligations, and returns a cited attack narrative with ATT&CK
                        mapping. Nothing leaves this machine.
                      </p>
                    </div>
                  )}
                </>
              ) : (
                !loading && <p className="p-6 text-sm text-muted-foreground">Select an alert to start triage.</p>
              )}
            </div>
          </div>
        )}
      </main>
      <EvidenceSheet report={report} id={evidenceId} onClose={() => setEvidenceId(null)} />
    </div>
  );
}
