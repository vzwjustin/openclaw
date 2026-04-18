import { evaluate } from "./engine.js";
import type { PolicyEventEnvelope } from "./events.js";
import { getNodeCapability } from "./node-capability-registry.js";
import type {
  ActionOutcome,
  ActionRequest,
  ActionResult,
  PolicyDecision,
  PolicyProfile,
} from "./types.js";

export interface BrokerPorts {
  policy: {
    forUser: (userId: string) => Promise<PolicyProfile>;
  };
  approvals: {
    create: (req: ActionRequest, decision: PolicyDecision) => Promise<{ id: string; subject: string }>;
    requireApproved: (approvalId: string) => Promise<boolean>;
  };
  execution: {
    invoke: (req: ActionRequest, opts: { skipApprovalCheck: boolean }) => Promise<ActionResult>;
  };
  events: {
    emit: (event: PolicyEventEnvelope<string, unknown>) => Promise<void>;
  };
  logger: {
    info: (msg: string, data?: unknown) => void;
    warn: (msg: string, data?: unknown) => void;
    error: (msg: string, data?: unknown) => void;
  };
}

export interface Broker {
  submit(req: ActionRequest): Promise<ActionOutcome>;
  resumeAfterApproval(approvalId: string, req: ActionRequest): Promise<ActionOutcome>;
}

let _idCounter = 0;
function newId(): string {
  return `pol-${Date.now()}-${++_idCounter}`;
}

function envelope<T extends string, P>(type: T, payload: P): PolicyEventEnvelope<T, P> {
  return {
    id: newId(),
    type,
    payload,
    createdAt: new Date().toISOString(),
  };
}

export function createBroker(ports: BrokerPorts): Broker {
  return {
    async submit(req: ActionRequest): Promise<ActionOutcome> {
      const cap = getNodeCapability(req.command);
      const profile = await ports.policy.forUser(req.userId);

      const decision = evaluate({
        userId: req.userId,
        profile,
        surface: req.surface,
        command: req.command,
        capabilityMeta: {
          sensitivity: cap.sensitivity,
          mutatesState: cap.mutatesState,
          approvalHint: cap.approvalHint,
          idempotent: cap.idempotent,
        },
        context: { originatingKind: "chat" },
      });

      await ports.events.emit(envelope("policy.decision", { req, decision }));

      if (decision.decision === "deny") {
        return { kind: "denied", reason: decision.reason };
      }

      if (decision.decision === "require_approval") {
        const approval = await ports.approvals.create(req, decision);
        return { kind: "approval_required", approvalId: approval.id };
      }

      return executeNow(req, ports);
    },

    async resumeAfterApproval(approvalId: string, req: ActionRequest): Promise<ActionOutcome> {
      const approved = await ports.approvals.requireApproved(approvalId);
      if (!approved) {
        return { kind: "denied", reason: "Approval was not granted." };
      }
      return executeNow(req, ports);
    },
  };
}

async function executeNow(req: ActionRequest, ports: BrokerPorts): Promise<ActionOutcome> {
  // system.run has a second approval gate inside sanitizeNodeInvokeParamsForForwarding.
  // When policy has already allowed the action, we pass skipApprovalCheck=true so the
  // inner gate does not block execution.
  const skipApprovalCheck = req.command === "system.run" || req.command === "system.write";

  await ports.events.emit(envelope("action.started", { req }));

  try {
    const result = await ports.execution.invoke(req, { skipApprovalCheck });
    if (!result.ok) {
      const errorMessage = result.errorMessage ?? "execution returned ok=false";
      ports.logger.error("[broker] execution not-ok", { command: req.command, errorMessage });
      await ports.events.emit(envelope("action.failed", { req, errorMessage }));
      return { kind: "failed", errorMessage };
    }
    await ports.events.emit(envelope("action.completed", { req, result }));
    return { kind: "allowed", result };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    ports.logger.error("[broker] execution failed", { command: req.command, errorMessage });
    await ports.events.emit(envelope("action.failed", { req, errorMessage }));
    return { kind: "failed", errorMessage };
  }
}
