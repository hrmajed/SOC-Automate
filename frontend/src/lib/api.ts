export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Verdict = "true_positive" | "suspicious" | "likely_benign";

export interface Alert {
  id: string;
  title: string;
  source: "edr" | "cloudtrail" | "idp";
  rule: string;
  severity: Severity;
  status: string;
  created_at: string;
  description: string;
  entities: { hosts: string[]; users: string[]; ips: string[] };
  evidence_refs: string[];
  ai_verdict: Verdict | null;
  ai_severity: Severity | null;
}

export interface Technique {
  id: string;
  name: string;
  tactic: string;
  url: string;
  evidence_ids?: string[];
}

export interface TimelineEntry {
  evidence_id: string;
  timestamp: string;
  source: string;
  host: string | null;
  user: string | null;
  event_type: string;
  summary: string;
  phrase: string;
  techniques: Technique[];
  score: number;
  malicious: boolean;
  injection: boolean;
  notes: string[];
}

export interface PathNode {
  id: string;
  label: string;
  kind: "host" | "identity" | "cloud" | "data";
  principals: string[];
  first_seen: string;
  last_seen: string;
  techniques: string[];
  evidence_ids: string[];
  detail: string;
}

export interface Finding {
  id: string;
  layer: "input" | "rag" | "tool" | "output";
  kind: string;
  severity: string;
  location: string;
  detail: string;
  action: string;
  snippet: string;
}

export interface Step {
  step: number;
  tool: string;
  args: Record<string, unknown>;
  args_display: Record<string, unknown>;
  allowed: boolean;
  reason: string;
  result_summary?: string;
  new_evidence?: string[];
  guardrail_findings?: Finding[];
}

export interface EvidenceRecord {
  evidence_id: string;
  source: string;
  timestamp: string;
  event_type: string;
  summary: string;
  host: string | null;
  user: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  outcome: string | null;
  fields: Record<string, unknown>;
  raw: Record<string, unknown>;
}

export interface Report {
  alert: Alert;
  verdict: Verdict;
  severity: Severity;
  confidence: string;
  risk_score: number;
  narrative: string;
  narrative_source: string;
  timeline: TimelineEntry[];
  attack_mapping: Technique[];
  attack_path: PathNode[];
  environment_context: {
    statement: string;
    doc_id: string | null;
    title: string;
    kind: string;
    trust: string;
    score: number;
    relevance: string;
  }[];
  recommended_actions: {
    id: string;
    action: string;
    rationale: string;
    evidence_ids: string[];
    priority: string;
    requires_approval: boolean;
  }[];
  evidence: Record<string, EvidenceRecord>;
  related_alerts: string[];
  steps: Step[];
  executed_forbidden: { tool: string; args: Record<string, unknown> }[];
  guardrails: {
    enabled: boolean;
    findings: Finding[];
    rag_blocked: { doc_id: string; title: string; reason: string }[];
    kb_quarantine: { doc_id: string; title: string; source: string; reason: string; snippet: string }[];
    spotlight_nonce: string | null;
  };
  pii: { unique_values_masked: number; by_type: Record<string, number>; replacements: number };
  llm: {
    backend: string;
    model: string;
    rounds: number;
    transcript: { role: string; content: string; tool_name?: string; tool_calls?: unknown[] }[];
  };
  metrics: { duration_ms: number; tool_calls: number; events_reviewed: number; llm_rounds: number; sources: string[] };
}

export interface Health {
  status: string;
  offline: boolean;
  llm: { backend: string; model: string };
  knowledge: { embedder: string; chunks: number; documents: number; quarantined: unknown[] };
  events: number;
  alerts: number;
}

export type StreamEvent =
  | { type: "phase"; phase: string; message: string }
  | ({ type: "tool_call" } & Step)
  | ({ type: "tool_result" } & Step)
  | { type: "error"; message: string; fatal?: boolean }
  | { type: "report"; report: Report };

export interface EvalCase {
  id: string;
  name: string;
  category: string;
  mode: string;
  description: string;
  attack_succeeded_off: boolean;
  attack_succeeded_on: boolean;
  controls: string[];
  blocked_by: string[];
  verdict_off: string;
  verdict_on: string;
  severity_off: string;
  severity_on: string;
}

export interface EvalResult {
  cases: EvalCase[];
  summary: {
    cases: number;
    asr_guardrails_off: number;
    asr_guardrails_on: number;
    false_positive_control: { fields_scanned: number; false_positives: string[]; passed: boolean };
    duration_ms: number;
  };
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => fetch("/api/health", { cache: "no-store" }).then(json<Health>),
  alerts: () => fetch("/api/alerts", { cache: "no-store" }).then(json<Alert[]>),
  report: (id: string) => fetch(`/api/reports/${id}`, { cache: "no-store" }).then((r) => (r.ok ? (r.json() as Promise<Report>) : null)),
  runEvals: () => fetch("/api/evals/run", { method: "POST" }).then(json<EvalResult>),
};

export async function investigateStream(
  alertId: string,
  opts: { guardrails: boolean; paceMs: number; signal?: AbortSignal },
  onEvent: (e: StreamEvent) => void,
): Promise<void> {
  const res = await fetch(
    `/api/alerts/${alertId}/investigate/stream?guardrails=${opts.guardrails}&pace_ms=${opts.paceMs}`,
    { method: "POST", signal: opts.signal },
  );
  if (!res.ok || !res.body) throw new Error(`Investigation failed: ${res.status} ${res.statusText}`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) onEvent(JSON.parse(line) as StreamEvent);
    }
  }
  if (buf.trim()) onEvent(JSON.parse(buf) as StreamEvent);
}
