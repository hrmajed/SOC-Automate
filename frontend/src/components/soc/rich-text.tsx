"use client";

import { Fragment } from "react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Report } from "@/lib/api";

const TOKEN = /(\*\*[^*]+\*\*|\[[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9.-]+\]|\[REDACTED[^\]]*\])/g;

export function Citation({ id, report, onOpen }: { id: string; report: Report; onOpen: (id: string) => void }) {
  const ev = report.evidence[id];
  const doc = report.environment_context.find((e) => e.doc_id === id);
  if (ev) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={() => onOpen(id)}
            className="mx-0.5 inline-flex items-center rounded border border-primary/30 bg-primary/10 px-1 font-mono text-[10.5px] leading-4 text-primary hover:bg-primary/20"
          >
            {id}
          </button>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">{ev.summary}</TooltipContent>
      </Tooltip>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="mx-0.5 inline-flex items-center rounded border border-violet-400/30 bg-violet-400/10 px-1 font-mono text-[10.5px] leading-4 text-violet-200">
          {id}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{doc ? `${doc.title}: ${doc.statement}` : "Knowledge-base document"}</TooltipContent>
    </Tooltip>
  );
}

export function RichText({ text, report, onOpen }: { text: string; report: Report; onOpen: (id: string) => void }) {
  return (
    <>
      {text.split(TOKEN).map((part, i) => {
        if (!part) return null;
        if (part.startsWith("**")) return <strong key={i} className="font-semibold text-foreground">{part.slice(2, -2)}</strong>;
        if (part.startsWith("[REDACTED"))
          return (
            <span key={i} className="rounded bg-red-500/15 px-1 text-[11px] text-red-300">
              {part.slice(1, -1)}
            </span>
          );
        if (part.startsWith("[")) return <Citation key={i} id={part.slice(1, -1)} report={report} onOpen={onOpen} />;
        return <Fragment key={i}>{part}</Fragment>;
      })}
    </>
  );
}
