"use client";

import { ShieldAlert } from "lucide-react";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { Report } from "@/lib/api";
import { Pill, SOURCE, SourceIcon, dayTime } from "./format";

export function EvidenceSheet({ report, id, onClose }: { report: Report | null; id: string | null; onClose: () => void }) {
  const ev = report && id ? report.evidence[id] : null;
  const tl = report?.timeline.find((t) => t.evidence_id === id);
  const injection = report?.guardrails.findings.find((f) => f.kind === "prompt_injection" && f.location.startsWith(id ?? "~"));
  return (
    <Sheet open={!!ev} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        {ev && (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2 font-mono text-base">
                <SourceIcon source={ev.source} /> {ev.evidence_id}
              </SheetTitle>
              <SheetDescription>
                {SOURCE[ev.source]?.label} · {ev.event_type} · {dayTime(ev.timestamp)}
              </SheetDescription>
            </SheetHeader>
            <div className="space-y-4 px-4 pb-6">
              <p className="text-sm">{ev.summary}</p>
              {tl && tl.techniques.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {tl.techniques.map((t) => (
                    <a key={t.id} href={t.url} target="_blank" rel="noreferrer">
                      <Pill className="border-primary/30 bg-primary/10 text-primary">
                        {t.id} · {t.name}
                      </Pill>
                    </a>
                  ))}
                </div>
              )}
              {injection && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm">
                  <div className="mb-1 flex items-center gap-2 font-medium text-red-300">
                    <ShieldAlert className="size-4" /> Prompt injection found in {injection.location.split(".").pop()}
                  </div>
                  <p className="text-red-200/90">{injection.detail}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    The field was redacted before the model saw it. The original text is kept here as evidence.
                  </p>
                </div>
              )}
              <div>
                <h4 className="mb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">Normalised fields</h4>
                <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 rounded-lg border bg-muted/30 p-3 text-xs">
                  {Object.entries({ host: ev.host, user: ev.user, src_ip: ev.src_ip, dst_ip: ev.dst_ip, outcome: ev.outcome, ...ev.fields })
                    .filter(([, v]) => v !== null && v !== undefined && v !== "")
                    .map(([k, v]) => (
                      <div key={k} className="contents">
                        <dt className="text-muted-foreground">{k}</dt>
                        <dd className="font-mono break-all">{String(v)}</dd>
                      </div>
                    ))}
                </dl>
              </div>
              <div>
                <h4 className="mb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">Raw event</h4>
                <pre className="max-h-80 overflow-auto rounded-lg border bg-black/40 p-3 font-mono text-[11px] leading-relaxed">
                  {JSON.stringify(ev.raw, null, 2)}
                </pre>
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
