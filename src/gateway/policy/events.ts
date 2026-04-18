export type PolicyNodeEventType =
  | "policy.decision"
  | "action.started"
  | "action.completed"
  | "action.failed";

export interface PolicyEventEnvelope<T extends string, P> {
  id: string;
  type: T;
  userId?: string;
  correlationId?: string;
  subject?: string;
  payload: P;
  createdAt: string;
}
