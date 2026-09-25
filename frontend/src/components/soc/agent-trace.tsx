"use client";

import {
  BookOpen,
  Check,
  CircleSlash,
  Cloud,
  Fingerprint,
  Globe,
  Laptop,
  Link2,
  Loader2,
  Server,
  ShieldAlert,
  UserRound,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useRef } from "react";
import type { Step } from "@/lib/api";
import { cn } from "@/lib/utils";

const TOOL_ICON: Record<string, LucideIcon> = {
  lookup_asset: Server,
  lookup_identity: UserRound,
  lookup_ip: Globe,
  query_edr: Laptop,
  query_cloudtrail: Cloud,
  query_idp: Fingerprint,
  search_knowledge: BookOpen,
  get_related_alerts: Link2,
};

function fmtArgs(args: Record<string, unknown>) {
  return Object.entries(args)
    .filter(([k]) => k !== "start" && k !== "end")
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(", ");
}

export function AgentTrace({ steps, running, phase }: { steps: Step[]; running: boolean; phase: string }) {
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (running) end.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [steps.length, running]);

  return (
    <div className="max-h-[420px] overflow-y-auto pr-1">
      <ol className="relative space-y-1 border-l border-border pl-4">
        {steps.map((s) => {
          const Icon = TOOL_ICON[s.tool] ?? CircleSlash;
          const flagged = (s.guardrail_findings?.length ?? 0) > 0;
          const pending = s.result_summary === undefined;
          return (
            <li key={s.step} className="relative">
              <span
                className={cn(
                  "absolute top-2 -left-[21px] flex size-2.5 rounded-full ring-4 ring-card",
                  !s.allowed ? "bg-red-400" : flagged ? "bg-amber-400" : pending ? "bg-muted-foreground" : "bg-primary",
                )}
              />
              <div
                className={cn(
                  "flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded-md px-2 py-1.5 text-[12.5px]",
                  !s.allowed && "bg-red-500/10",
                  flagged && "bg-amber-500/10",
                )}
              >
                <Icon className="size-3.5 text-muted-foreground" />
                <span className="font-mono font-medium">{s.tool}</span>
                <span className="truncate font-mono text-[11.5px] text-muted-foreground">({fmtArgs(s.args)})</span>
                <span className="ml-auto flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
                  {pending ? (
                    <Loader2 className="size-3 animate-spin" />
                  ) : !s.allowed ? (
                    <span className="text-red-300">blocked: {s.reason}</span>
                  ) : (
                    <>
                      <Check className="size-3 text-primary" />
                      {s.result_summary}
                      {!!s.new_evidence?.length && <span className="text-primary">+{s.new_evidence.length} evidence</span>}
                    </>
                  )}
                </span>
              </div>
              {s.guardrail_findings?.map((f) => (
                <div key={f.id} className="ml-6 flex items-center gap-1.5 py-0.5 text-[11.5px] text-amber-200">
                  <ShieldAlert className="size-3" /> {f.kind.replace(/_/g, " ")} in {f.location} · {f.action}
                </div>
              ))}
            </li>
          );
        })}
        {running && (
          <li className="flex items-center gap-2 px-2 py-1.5 text-[12.5px] text-muted-foreground">
            <Loader2 className="size-3.5 animate-spin text-primary" /> {phase}
          </li>
        )}
      </ol>
      <div ref={end} />
    </div>
  );
}
