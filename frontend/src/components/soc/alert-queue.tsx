"use client";

import { Sparkles } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import type { Alert } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Pill, SeverityPill, SourceIcon, VERDICT, dayTime } from "./format";

export function AlertQueue({
  alerts,
  selected,
  onSelect,
  loading,
}: {
  alerts: Alert[];
  selected: string | null;
  onSelect: (id: string) => void;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="space-y-2 p-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-[84px] w-full rounded-lg" />
        ))}
      </div>
    );
  }
  if (!alerts.length) {
    return <p className="p-6 text-sm text-muted-foreground">No open alerts. The queue is clear.</p>;
  }
  return (
    <ul className="space-y-1.5 p-2">
      {alerts.map((a) => (
        <li key={a.id}>
          <button
            onClick={() => onSelect(a.id)}
            className={cn(
              "w-full rounded-lg border border-transparent p-3 text-left transition-colors hover:bg-accent/60",
              selected === a.id && "border-primary/40 bg-accent",
            )}
          >
            <div className="flex items-center gap-2">
              <SourceIcon source={a.source} className="size-3.5" />
              <span className="font-mono text-[11px] text-muted-foreground">{a.id}</span>
              <span className="ml-auto">
                <SeverityPill severity={a.severity} />
              </span>
            </div>
            <p className="mt-1.5 line-clamp-2 text-[13px] leading-snug font-medium">{a.title}</p>
            <div className="mt-1.5 flex items-center gap-2 text-[11px] text-muted-foreground">
              <span>{dayTime(a.created_at)}</span>
              {a.ai_verdict ? (
                <Pill className={cn("ml-auto", VERDICT[a.ai_verdict].style)}>
                  <Sparkles className="size-3" /> {VERDICT[a.ai_verdict].label}
                </Pill>
              ) : (
                <span className="ml-auto">New</span>
              )}
            </div>
          </button>
        </li>
      ))}
    </ul>
  );
}
