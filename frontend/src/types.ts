export type OutcomeType = "allow" | "allow_narrower" | "hold" | "deny";

export interface UserSession {
  sub: string;
  name: string;
  role: string;
}

export interface SessionStatus {
  session_id: string;
  tainted: boolean;
  taint_info?: {
    reason?: string;
    source_tool?: string;
    tainted_at?: string;
    has_downscoped_token?: boolean;
  };
}

export interface AgentClient {
  client_id: string;
  client_name: string;
  grant_types?: string[];
  redirect_uris?: string[];
}

export interface DecodedToken {
  sub: string;
  client_id: string;
  aud: string;
  task_id?: string;
  exp: number;
  iat?: number;
  jti: string;
  cnf?: { jkt: string };
  authorization_details?: Array<{
    type: string;
    server: string;
    tools: string[];
    actions?: string[];
  }>;
  act?: { sub: string };
  raw_token?: string;
}

export interface ModelScores {
  intent_match?: number;
  overreach?: number;
  reversibility?: number;
  injection_risk?: number;
  sensitivity?: number;
  poisoning_risk?: number;
  semantic_drift?: number;
  [key: string]: number | undefined;
}

export interface TimelineStep {
  step_number: number;
  tool: string;
  args_summary: string;
  outcome: OutcomeType;
  reason_code: string;
  latency_ms: number;
  scores?: ModelScores;
  policy_layer: "RBAC" | "PBAC" | "quota" | "ABAC" | string;
  explanation?: string;
  server?: string;
  auth_req_id?: string;
  requires_step_up?: boolean;
  tainted_after?: boolean;
  downscoped_token?: string;
}

export interface ScenarioPreset {
  id: string;
  name: string;
  description: string;
  default_instruction: string;
  expected_outcome: string;
}

export interface HeldCall {
  auth_req_id: string;
  tool: string;
  arguments: Record<string, any>;
  user_id: string;
  client_id: string;
  task: string;
  explanation: string;
  is_sensitive: boolean;
  requires_step_up: boolean;
  status: string;
  created_at: string;
  expires_in: number;
}

export interface RegisteredTool {
  tool_name: string;
  server_uri: string;
  description: string;
  description_sha256: string;
  approved_at: string;
  status: "approved" | "quarantined" | string;
  risk_tier: string;
}

export interface QuotaItem {
  tool: string;
  calls_last_min: number;
  limit: number;
  percentage: number;
  status: string;
}

export interface QuotaData {
  client_id: string;
  limits: Record<string, any>;
  usage: QuotaItem[];
  circuit_breaker: string;
}

export interface AuditRecord {
  index: number;
  ts: string;
  request_id: string;
  user_id: string;
  client_id: string;
  task_id: string;
  server: string;
  tool: string;
  args_sha256: string;
  policy_version: string;
  model_name: string;
  model_version: string;
  scores: Record<string, number>;
  outcome: OutcomeType | string;
  reason_code?: string;
  latency_ms: number;
  prev_hash: string;
  record_hash: string;
}

export interface EvalMetric {
  metric: string;
  jev: string;
  decision1: string;
  baseline: string;
}

export interface EvalResults {
  chart_data: Array<{
    fpr: number;
    Jev: number;
    Decision1: number;
    Baseline: number;
  }>;
  operating_point: {
    name: string;
    fpr: number;
    tpr: number;
  };
  metrics_table: EvalMetric[];
  report_url: string;
}
