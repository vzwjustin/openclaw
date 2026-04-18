export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
export type Decision = "allow" | "require_approval" | "deny";

export type NodeSurface = "node" | "plugin" | "hook" | "cron" | "agent-tool";

export interface NodeCapability {
  surface: NodeSurface;
  id: string;
  mutatesState: boolean;
  sensitivity: RiskLevel;
  idempotent: boolean;
  approvalHint: "never" | "sometimes" | "always";
}

export interface CapabilityMeta {
  sensitivity: RiskLevel;
  mutatesState: boolean;
  approvalHint: "never" | "sometimes" | "always";
  idempotent: boolean;
}

export interface PolicyRule {
  id: string;
  surface?: string;
  command?: string;
  when?: {
    mutatesState?: boolean;
    sensitivityAtLeast?: RiskLevel;
    bulkOver?: number;
  };
  decision: Decision;
  reason: string;
}

export interface PolicyProfile {
  id: string;
  name: string;
  kind: "builtin" | "custom";
  rules: PolicyRule[];
}

export interface PolicyInput {
  userId: string;
  profile: PolicyProfile;
  surface: NodeSurface;
  command: string;
  capabilityMeta: CapabilityMeta;
  context: {
    originatingKind: "chat" | "task";
    taskTrustLevel?: "low" | "normal" | "elevated";
    targetCount?: number;
    targetExamples?: unknown[];
  };
}

export interface PolicyDecision {
  decision: Decision;
  reason: string;
  rule: string;
  approvalTemplate?: "single" | "bulk";
}

export type ActionResult = {
  ok: boolean;
  output: unknown;
  errorMessage?: string;
};

export interface ActionRequest {
  idempotencyKey: string;
  userId: string;
  surface: NodeSurface;
  nodeId: string;
  command: string;
  input: Record<string, unknown>;
  sensitivityHint?: RiskLevel;
  correlationId: string;
}

export type ActionOutcome =
  | { kind: "allowed"; result: ActionResult }
  | { kind: "approval_required"; approvalId: string }
  | { kind: "denied"; reason: string }
  | { kind: "failed"; errorMessage: string };
