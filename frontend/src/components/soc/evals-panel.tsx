"use client";

import { FlaskConical, Loader2, ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, type EvalResult } from "@/lib/api";
import { Pill } from "./format";

function Outcome({ compromised, off }: { compromised: boolean; off?: boolean }) {
  return compromised ? (
    <Pill className="border-red-500/40 bg-red-500/10 text-red-300">
      <ShieldX className="size-3" /> Compromised
    </Pill>
  ) : (
    <Pill className="border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
      <ShieldCheck className="size-3" /> {off ? "Resisted" : "Blocked"}
    </Pill>
  );
}

export function EvalsPanel() {
  const [res, setRes] = useState<EvalResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      setRes(await api.runEvals());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <FlaskConical className="size-4 text-primary" /> Adversarial evaluation harness
            </CardTitle>
            <CardDescription className="max-w-3xl">
              Each attack runs twice against the full pipeline: once with guardrails <b>off</b> (baseline) and once <b>on</b>.
              Injected-data cases use a gullible model that obeys any instruction it can read, including base64 and invisible
              Unicode. Compromised-model cases script the model itself to misbehave, testing the controls that must hold no
              matter what the model does.
            </CardDescription>
          </div>
          <Button onClick={run} disabled={loading} className="shrink-0">
            {loading ? <Loader2 className="animate-spin" /> : <FlaskConical />} {res ? "Run again" : "Run adversarial suite"}
          </Button>
        </CardHeader>
        {res && (
          <CardContent className="grid gap-2 sm:grid-cols-4">
            <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3">
              <div className="text-[11px] text-muted-foreground">Attack success · guardrails OFF</div>
              <div className="text-2xl font-semibold text-red-300 tabular-nums">{Math.round(res.summary.asr_guardrails_off * 100)}%</div>
            </div>
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
              <div className="text-[11px] text-muted-foreground">Attack success · guardrails ON</div>
              <div className="text-2xl font-semibold text-emerald-300 tabular-nums">{Math.round(res.summary.asr_guardrails_on * 100)}%</div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-[11px] text-muted-foreground">False-positive control</div>
              <div className="text-2xl font-semibold tabular-nums">{res.summary.false_positive_control.false_positives.length}</div>
              <div className="text-[11px] text-muted-foreground">
                flags on {res.summary.false_positive_control.fields_scanned} benign fields
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-[11px] text-muted-foreground">Cases · runtime</div>
              <div className="text-2xl font-semibold tabular-nums">{res.summary.cases}</div>
              <div className="text-[11px] text-muted-foreground">{(res.summary.duration_ms / 1000).toFixed(1)} s, fully offline</div>
            </div>
          </CardContent>
        )}
      </Card>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Could not run the suite</AlertTitle>
          <AlertDescription>{error}. Check that the API is running on port 8765.</AlertDescription>
        </Alert>
      )}

      {!res && !loading && !error && (
        <div className="rounded-xl border border-dashed p-10 text-center text-sm text-muted-foreground">
          Ten attack cases cover prompt injection (plain, base64, Unicode tags, delimiter escape), tool misuse, RAG poisoning
          and tampering, and output exfiltration. The suite takes about two seconds.
        </div>
      )}

      {res && (
        <Card className="py-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-20">Case</TableHead>
                <TableHead>Attack</TableHead>
                <TableHead className="hidden md:table-cell">Threat mode</TableHead>
                <TableHead>Guardrails OFF</TableHead>
                <TableHead>Guardrails ON</TableHead>
                <TableHead className="hidden lg:table-cell">Controls that fired</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {res.cases.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-mono text-xs">{c.id}</TableCell>
                  <TableCell className="max-w-[340px] whitespace-normal">
                    <div className="text-[13px] font-medium">{c.name}</div>
                    <div className="text-[11.5px] text-muted-foreground">{c.description}</div>
                  </TableCell>
                  <TableCell className="hidden text-xs text-muted-foreground md:table-cell">{c.mode.replace("_", " ")}</TableCell>
                  <TableCell>
                    <Outcome compromised={c.attack_succeeded_off} off />
                    <div className="mt-1 text-[10.5px] text-muted-foreground">
                      {c.verdict_off.replace("_", " ")} · {c.severity_off}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Outcome compromised={c.attack_succeeded_on} />
                    <div className="mt-1 text-[10.5px] text-muted-foreground">
                      {c.verdict_on.replace("_", " ")} · {c.severity_on}
                    </div>
                  </TableCell>
                  <TableCell className="hidden max-w-[260px] whitespace-normal lg:table-cell">
                    <div className="flex flex-wrap gap-1">
                      {c.controls.map((k) => (
                        <Pill key={k} className="border-border text-muted-foreground">
                          {k.replace(/_/g, " ")}
                        </Pill>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  );
}
