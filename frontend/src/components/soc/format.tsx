import { Cloud, Fingerprint, Laptop, type LucideIcon } from "lucide-react";
import type { Severity, Verdict } from "@/lib/api";
import { cn } from "@/lib/utils";

export const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 border-red-500/40",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/15 text-amber-200 border-amber-500/40",
  low: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  info: "bg-slate-500/15 text-slate-300 border-slate-500/40",
};

export const VERDICT: Record<Verdict, { label: string; style: string }> = {
  true_positive: { label: "True positive", style: "bg-red-500/15 text-red-300 border-red-500/40" },
  suspicious: { label: "Suspicious", style: "bg-amber-500/15 text-amber-200 border-amber-500/40" },
  likely_benign: { label: "Likely benign", style: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40" },
};

export const SOURCE: Record<string, { label: string; icon: LucideIcon; tint: string }> = {
  edr: { label: "EDR", icon: Laptop, tint: "text-violet-300" },
  cloudtrail: { label: "CloudTrail", icon: Cloud, tint: "text-amber-300" },
  idp: { label: "Okta", icon: Fingerprint, tint: "text-sky-300" },
};

export function Pill({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center gap-1 rounded-full border px-2 text-[11px] font-medium whitespace-nowrap",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function SeverityPill({ severity }: { severity: Severity }) {
  return <Pill className={SEVERITY_STYLE[severity]}>{severity.toUpperCase()}</Pill>;
}

export function SourceIcon({ source, className }: { source: string; className?: string }) {
  const s = SOURCE[source] ?? SOURCE.edr;
  const Icon = s.icon;
  return <Icon className={cn("size-4", s.tint, className)} aria-label={s.label} />;
}

export function hhmm(ts: string) {
  return ts.slice(11, 19);
}

export function dayTime(ts: string) {
  const d = new Date(ts);
  return d.toLocaleString("en-GB", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
}
